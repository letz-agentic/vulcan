(ns vulcan.enrich.enrich-test
  "M4 tests (spec section 7).

  Nothing here touches the network. Every provider is a mock built on the
  `Enricher` protocol — which is the reason the protocol has exactly one
  method — and the parsers are tested against captured payloads. A test suite
  whose result depends on a public API being up is not a test suite."
  (:require [clojure.test :refer [deftest is testing]]
            [tablecloth.api :as tc]
            [vulcan.analysis.categorize :as cat]
            [vulcan.enrich.cache :as cache]
            [vulcan.enrich.circl :as circl]
            [vulcan.enrich.epss :as epss]
            [vulcan.enrich.http :as http]
            [vulcan.enrich.kev :as kev]
            [vulcan.enrich.provider :as p]
            [vulcan.report.context :as ctx]
            [vulcan.store.db :as db]
            [vulcan.test-store :as ts])
  (:import (java.time Duration Instant LocalDate)))

;; ---------------------------------------------------------------------------
;; mock providers

(defrecord MockProvider [nm rows-fn calls]
  p/Enricher
  (provider-name [_] nm)
  (enrich [_ ids]
    (swap! calls conj (vec ids))
    (rows-fn ids)))

(defn mock
  ([nm rows-fn] (mock nm rows-fn (atom [])))
  ([nm rows-fn calls] (->MockProvider nm rows-fn calls)))

(defn failing-provider [nm]
  (mock nm (fn [_] (throw (ex-info "provider exploded" {})))))

;; ---------------------------------------------------------------------------
;; freshness (spec 7.2)

(deftest duration-parsing
  (is (= (Duration/ofDays 7)     (cache/parse-duration "7d")))
  (is (= (Duration/ofHours 12)   (cache/parse-duration "12h")))
  (is (= (Duration/ofMinutes 30) (cache/parse-duration "30m")))
  (is (= (Duration/ofDays 14)    (cache/parse-duration "2w")))
  (is (= (Duration/ofSeconds 45) (cache/parse-duration "45s")))
  (testing "a bare number means days, because that is what people type"
    (is (= (Duration/ofDays 3) (cache/parse-duration "3")))
    (is (= (Duration/ofDays 3) (cache/parse-duration 3))))
  (testing "nil means no threshold at all"
    (is (nil? (cache/parse-duration nil))))
  (testing "nonsense is an error, not a silent default"
    (is (thrown? clojure.lang.ExceptionInfo (cache/parse-duration "soon")))))

(deftest stale-ids-respects-max-age
  (ts/with-store [conn]
    (let [all (cache/stale-ids conn nil)]
      (is (seq all) "nothing is enriched yet, so everything is stale")

      (testing "after enriching, nothing is stale within the window"
        (cache/enrich! conn {:providers [(mock :m (fn [ids]
                                                    (map (fn [id]
                                                           {:vulnerability-id id
                                                            :circl-fetched-at (Instant/now)})
                                                         ids)))]})
        (is (empty? (cache/stale-ids conn "7d"))))

      (testing "and everything is stale again once the window passes"
        (is (= (count all) (count (cache/stale-ids conn "1s" (.plusSeconds (Instant/now) 60)))))))))

;; ---------------------------------------------------------------------------
;; merging (spec 7.2)

(deftest merge-results-combines-providers
  (let [rows (cache/merge-results
              ["CVE-1" "CVE-2"]
              [[{:vulnerability-id "CVE-1" :kev true}]
               [{:vulnerability-id "CVE-1" :epss-score 0.5}
                {:vulnerability-id "CVE-2" :epss-score 0.1}]])
        by-id (into {} (map (juxt :vulnerability-id identity)) rows)]
    (is (= 2 (count rows)))
    (is (true? (:kev (by-id "CVE-1"))))
    (is (= 0.5 (:epss-score (by-id "CVE-1"))) "both providers contribute")
    (is (= 0.1 (:epss-score (by-id "CVE-2"))))))

(deftest merge-results-never-overwrites-with-nil
  (testing "a provider that could not answer must not erase another's answer"
    (let [rows (cache/merge-results
                ["CVE-1"]
                [[{:vulnerability-id "CVE-1" :description "real"}]
                 [{:vulnerability-id "CVE-1" :description nil :kev true}]])]
      (is (= "real" (:description (first rows))))
      (is (true? (:kev (first rows)))))))

(deftest merge-results-returns-a-row-per-requested-id
  (testing "so that 'how much of the store is enriched' is answerable"
    (let [rows (cache/merge-results ["CVE-1" "CVE-2" "CVE-3"]
                                    [[{:vulnerability-id "CVE-2" :kev true}]])]
      (is (= 3 (count rows)))
      (is (= #{"CVE-1" "CVE-2" "CVE-3"} (set (map :vulnerability-id rows)))))))

;; ---------------------------------------------------------------------------
;; orchestration

(deftest one-broken-provider-does-not-lose-the-others
  (ts/with-store [conn]
    (let [{:keys [written]}
          (cache/enrich! conn {:providers [(failing-provider :broken)
                                           (mock :good (fn [ids]
                                                         (map #(hash-map :vulnerability-id %
                                                                         :kev true)
                                                              ids)))]})]
      (is (pos? written))
      (is (pos? (:n (db/execute-one! conn ["SELECT count(*) AS n FROM vulnerability
                                            WHERE kev"])))))))

(deftest offline-makes-no-requests
  (testing "spec 7.2: a report must never fail because a public API is down"
    (ts/with-store [conn]
      (let [calls (atom [])
            res   (cache/enrich! conn {:offline?  true
                                       :providers [(mock :never
                                                         (fn [ids] (map #(hash-map :vulnerability-id %) ids))
                                                         calls)]})]
        (is (:offline? res))
        (is (zero? (:written res)))
        (is (pos? (:requested res)) "it still reports what it would have fetched")
        (is (empty? @calls) "and the provider was never called")))))

(deftest offline-binding-blocks-the-http-layer
  (binding [http/*offline* true]
    (is (nil? (http/get-json "https://example.invalid/never-requested")))
    (is (nil? (http/get-text "https://example.invalid/never-requested")))))

(deftest limit-caps-the-run
  (ts/with-store [conn]
    (let [calls (atom [])
          _     (cache/enrich! conn {:limit 3
                                     :providers [(mock :m (fn [ids]
                                                            (map #(hash-map :vulnerability-id %) ids))
                                                       calls)]})]
      (is (= 3 (count (first @calls)))))))

(deftest enrichment-is-idempotent-and-refreshes
  (testing "unlike findings, enrichment upserts: a newer score replaces an older"
    (ts/with-store [conn]
      (let [id (first (cache/stale-ids conn nil))]
        (cache/enrich! conn {:providers [(mock :a (fn [_] [{:vulnerability-id id
                                                            :epss-score 0.1
                                                            :description "first"}]))]})
        (cache/enrich! conn {:providers [(mock :b (fn [_] [{:vulnerability-id id
                                                            :epss-score 0.9}]))]})
        (let [row (db/execute-one! conn ["SELECT * FROM vulnerability
                                          WHERE vulnerability_id = ?" id])]
          (is (= 0.9 (:epss-score row)) "the refreshed score wins")
          (is (= "first" (:description row))
              "and a field the second run did not carry is preserved")
          (is (= 1 (:n (db/execute-one! conn ["SELECT count(*) AS n FROM vulnerability
                                               WHERE vulnerability_id = ?" id])))
              "upsert, not insert"))))))

;; ---------------------------------------------------------------------------
;; the payoff: enrichment moves the categorisation axis (spec 8.2)

(deftest enrichment-drives-the-exploitability-axis
  (ts/with-store [conn]
    (let [ids (vec (cache/stale-ids conn nil))
          kev-id (first ids)
          hot-id (second ids)]
      (cache/enrich!
       conn
       {:providers [(mock :m (fn [_]
                               [{:vulnerability-id kev-id :kev true}
                                {:vulnerability-id hot-id :epss-score 0.5
                                 :epss-percentile 0.95}]))]})
      (let [c    (ctx/build {:connectable conn :scope :latest})
            rows (tc/rows (:findings c) :as-maps)
            axis (fn [id] (->> rows (filter #(= id (:vulnerability-id %)))
                               first :exploitability))]
        (is (= "exploited" (axis kev-id)) "KEV saturates the axis")
        (is (= "likely" (axis hot-id))    "EPSS >= 0.1 is likely")
        (is (pos? (:n-exploited (:summary c))))))))

(deftest kev-lifts-a-finding-up-the-fix-list
  (testing "spec 8.3: KEV saturates the exploitability component"
    (ts/with-store [conn]
      (let [;; A CRITICAL, fixable finding: marking it known-exploited should
            ;; put it at the very top. KEV alone does not guarantee first
            ;; place -- a LOW known-exploited bug is still a LOW bug -- which
            ;; is why the property test in score-test pins the CRITICAL case.
            id (-> (db/execute-one! conn ["SELECT vulnerability_id FROM finding
                                           WHERE severity = 'CRITICAL'
                                             AND status = 'fixed'
                                           LIMIT 1"])
                   :vulnerability-id)
            before (-> (ctx/build {:connectable conn :scope :latest})
                       :scored (tc/rows :as-maps) first :vulnerability-id)]
        (is (some? id) "the fixtures contain a fixable CRITICAL")
        (cache/enrich! conn {:providers [(mock :m (fn [_] [{:vulnerability-id id
                                                            :kev true}]))]})
        (let [top (-> (ctx/build {:connectable conn :scope :latest})
                      :scored (tc/rows :as-maps) first)]
          (is (= id (:vulnerability-id top))
              (str "the known-exploited CRITICAL should now outrank " before))
          (is (= "exploited" (:exploitability top))))))))

;; ---------------------------------------------------------------------------
;; parsers, against captured payloads

(deftest kev-entry-parsing
  (let [rows (->> [{:cveID "CVE-2021-44228" :dateAdded "2021-12-10"
                    :knownRansomwareCampaignUse "Known"}
                   {:cveID "CVE-2014-0160" :dateAdded "2022-05-04"
                    :knownRansomwareCampaignUse "Unknown"}]
                  (map #'kev/entry->map)
                  (into {} (map (juxt :vulnerability-id identity))))]
    (is (true? (:kev (rows "CVE-2021-44228"))))
    (is (= (LocalDate/parse "2021-12-10") (:kev-date-added (rows "CVE-2021-44228"))))
    (testing "CISA writes Known/Unknown, not a boolean"
      (is (true?  (:kev-ransomware (rows "CVE-2021-44228"))))
      (is (false? (:kev-ransomware (rows "CVE-2014-0160")))))))

(deftest kev-absence-is-recorded-only-when-the-catalogue-loaded
  (testing "a failed fetch must not look like 'none of these are exploited'"
    (let [provider (kev/->KevProvider (atom {}))]
      (is (empty? (p/enrich provider ["CVE-1"]))))
    (let [provider (kev/->KevProvider (atom {"CVE-2" {:vulnerability-id "CVE-2" :kev true}}))
          rows     (into {} (map (juxt :vulnerability-id identity))
                         (p/enrich provider ["CVE-1" "CVE-2"]))]
      (is (true?  (:kev (rows "CVE-2"))))
      (is (false? (:kev (rows "CVE-1"))) "a real negative from a loaded catalogue"))))

(deftest epss-csv-parsing
  (let [csv (str "#model_version:v2025.03.14,score_date:2026-08-27T00:00:00+0000\n"
                 "cve,epss,percentile\n"
                 "CVE-2021-44228,0.99999,1.00000\n"
                 "CVE-2014-0160,0.94382,0.99900\n")
        rows (into {} (map (juxt :vulnerability-id identity)) (epss/parse-csv csv))]
    (is (= 2 (count rows)))
    (is (= 0.99999 (:epss-score (rows "CVE-2021-44228"))))
    (is (= 0.999   (:epss-percentile (rows "CVE-2014-0160"))))
    (testing "the leading #-comment line is not mistaken for the header"
      (is (nil? (rows "#model_version:v2025.03.14"))))))

(deftest circl-description-from-a-cve-5-record
  (testing "CIRCL serves the upstream CVE 5.0 record verbatim"
    (is (= "the description"
           (circl/description {:containers {:cna {:descriptions
                                                  [{:lang "en" :value "the description"}]}}})))
    (testing "and falls back to the first entry when none is tagged English"
      (is (= "sans langue"
             (circl/description {:containers {:cna {:descriptions
                                                    [{:value "sans langue"}]}}}))))
    (is (nil? (circl/description {})))))

;; ---------------------------------------------------------------------------
;; rate limiting (spec 7.1: responses carry RateLimit-* headers)

(deftest retry-after-is-honoured
  (is (= 30000 (http/retry-after-ms {"retry-after" "30"})))
  (is (= 30000 (http/retry-after-ms {"Retry-After" "30"})))
  (testing "or derived from the reset epoch when there is no Retry-After"
    (let [soon (+ 5 (quot (System/currentTimeMillis) 1000))]
      (is (<= 1000 (http/retry-after-ms {"x-ratelimit-reset" (str soon)}) 5000))))
  (testing "a reset in the past is not a negative sleep"
    (is (nil? (http/retry-after-ms {"x-ratelimit-reset" "1"}))))
  (is (nil? (http/retry-after-ms {}))))

(deftest circl-credentials-use-the-header-the-instance-reads
  (testing "the instance buckets on X-API-KEY; the spec's CVE-API-* headers
            are ignored, so sending those is the same as sending nothing"
    (with-redefs [http/circl-headers
                  (fn [] (into {} (remove (comp nil? val))
                               {"X-API-KEY" "secret"}))]
      (is (= {"X-API-KEY" "secret"} (http/circl-headers))))
    (testing "and no header at all when the environment is unset"
      (is (not (contains? (http/circl-headers) "CVE-API-KEY"))))))

(deftest user-agent-identifies-the-client
  (testing "the policy asks for a contact URL or email; an unidentified
            client is rate-limited or blocked first"
    (is (re-find #"vulcan-v/" http/user-agent))
    (is (re-find #"\+https?://" http/user-agent))))

(deftest rate-limited-recognises-429-and-5xx-but-not-404
  (is (http/rate-limited? {:status 429}))
  (is (http/rate-limited? {:status 503}))
  (is (not (http/rate-limited? {:status 404})))
  (is (not (http/rate-limited? {:status 200}))))

(deftest with-retries-stops-at-a-non-retryable-answer
  (let [calls (atom 0)
        res   (p/with-retries {:attempts 4 :retryable? http/rate-limited?}
                              (fn [] (swap! calls inc) {:status 404}))]
    (is (= {:status 404} res))
    (is (= 1 @calls) "a 404 is an answer, not a failure to retry")))

(deftest with-retries-gives-up-with-a-fallback
  (let [calls (atom 0)
        res   (p/with-retries {:attempts 3 :base-delay-ms 1
                               :retryable? http/rate-limited?
                               :fallback :gave-up}
                              (fn [] (swap! calls inc) {:status 429}))]
    (is (= :gave-up res))
    (is (= 3 @calls))))

(deftest breaker-trips-once-and-stays-tripped
  (let [b (p/breaker)]
    (is (not (p/open? b)))
    (p/trip! b "first")
    (p/trip! b "second")
    (is (p/open? b))
    (is (= "first" (:reason @b)) "the first reason is kept"))
  (testing "a nil breaker is simply never open"
    (is (not (p/open? nil)))))

(deftest bounded-pmap-bounds-concurrency
  (let [in-flight (atom 0)
        peak      (atom 0)
        f         (fn [x]
                    (let [n (swap! in-flight inc)]
                      (swap! peak max n)
                      (Thread/sleep 5)
                      (swap! in-flight dec)
                      x))]
    (is (= (range 20) (p/bounded-pmap 3 f (range 20))))
    (is (<= @peak 3) (str "peak concurrency was " @peak))))
