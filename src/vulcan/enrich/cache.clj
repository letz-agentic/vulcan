(ns vulcan.enrich.cache
  "Enrichment freshness and orchestration (spec section 7.2).

  The lab work's file-backed EDN cache becomes the `vulnerability` table
  itself: `circl_fetched_at` is the cache timestamp, and `circl_raw` is the
  cached payload. There is no second store to keep in sync, and a report's
  provenance appendix can state the cache age because the cache *is* the data.

  Two rules this namespace exists to enforce:

  1. **Only fetch what is stale.** `bb enrich --max-age 7d` looks up ids that
     are missing or older than the threshold, and nothing else.
  2. **A report never fails because a public API is down.** Providers degrade
     to returning nothing, an offline run makes no requests at all, and what
     is already cached is what gets rendered — stamped with its age."
  (:require [clojure.string :as str]
            [clojure.tools.logging :as log]
            [vulcan.enrich.circl :as circl]
            [vulcan.enrich.epss :as epss]
            [vulcan.enrich.http :as http]
            [vulcan.enrich.kev :as kev]
            [vulcan.enrich.provider :as p]
            [vulcan.store.db :as db]
            [vulcan.store.query :as q]
            [vulcan.store.write :as write])
  (:import (java.time Duration Instant)))

;; ---------------------------------------------------------------------------
;; freshness

(def duration-re #"^(\d+)\s*([smhdw])$")

(defn parse-duration
  "`7d`, `12h`, `30m`, `2w` -> a Duration. Also accepts a bare number of days,
  because that is what people type."
  [s]
  (cond
    (nil? s) nil
    (instance? Duration s) s
    (number? s) (Duration/ofDays (long s))
    :else
    (let [t (str/trim (str s))]
      (if-let [[_ n unit] (re-matches duration-re (str/lower-case t))]
        (let [n (parse-long n)]
          (case unit
            "s" (Duration/ofSeconds n)
            "m" (Duration/ofMinutes n)
            "h" (Duration/ofHours n)
            "d" (Duration/ofDays n)
            "w" (Duration/ofDays (* 7 n))))
        (if-let [n (parse-long t)]
          (Duration/ofDays n)
          (throw (ex-info "Unparseable duration; expected forms like 7d, 12h, 30m, 2w"
                          {:input s})))))))

(defn stale-before
  "The instant before which cached enrichment counts as stale."
  [max-age now]
  (when-let [d (parse-duration max-age)]
    (.minus ^Instant now ^Duration d)))

(defn stale-ids
  "Vulnerability ids in the store that need enriching: never fetched, or
  fetched longer ago than `max-age`. With no `max-age`, everything.

  Freshness keys on `circl_fetched_at`, the one signal that can come back
  empty because of a rate limit. A row that got EPSS and KEV but no
  description therefore stays stale and is retried on the next run, which is
  the behaviour we want; re-asking the two bulk feeds costs one request each."
  ([connectable] (stale-ids connectable nil))
  ([connectable max-age] (stale-ids connectable max-age (Instant/now)))
  ([connectable max-age now]
   (q/vulnerability-ids connectable (stale-before max-age now))))

;; ---------------------------------------------------------------------------
;; merging provider results

(defn merge-results
  "Combine partial rows from several providers into one row per id.

  Later providers win on conflict, so the order in `run-providers` is the
  precedence order. Nils never overwrite a value: a provider that could not
  answer must not erase what another one found."
  [requested-ids results]
  (let [merged (reduce (fn [acc row]
                         (if-let [id (:vulnerability-id row)]
                           (update acc id
                                   (fn [existing]
                                     (merge existing
                                            (into {} (remove (comp nil? val)) row))))
                           acc))
                       {}
                       (apply concat results))]
    ;; Every id we asked about gets a row, even an empty one: that is what
    ;; makes "how much of the store is enriched" answerable, and it stops the
    ;; next run from treating an id with genuinely no data as perpetually new.
    (mapv (fn [id]
            (merge {:vulnerability-id id}
                   (get merged id)))
          requested-ids)))

;; ---------------------------------------------------------------------------
;; running

(defn default-providers
  "The providers a plain `bb enrich` uses.

  Order is precedence order, cheapest and most authoritative first: bulk KEV,
  then bulk EPSS, then per-id CIRCL for descriptions."
  [{:keys [concurrency sightings?] :or {concurrency 4}}]
  [(kev/provider)
   (epss/api-provider concurrency)
   ;; CIRCL keeps its own, lower concurrency: it is the one rate-limited
   ;; per-id source, and letting it inherit a high `--concurrency` meant for
   ;; the bulk providers just buys 429s.
   (circl/provider {:concurrency (min concurrency circl/default-concurrency)
                    :sightings?  sightings?})])

(defn run-providers
  "Ask each provider about `ids`. A provider that throws is logged and skipped
  — one broken source must not cost us the other three."
  [providers ids]
  (for [provider providers]
    (try
      (let [rows (vec (p/enrich provider ids))]
        (log/infof "%s: %d rows for %d ids"
                   (name (p/provider-name provider)) (count rows) (count ids))
        rows)
      (catch Exception e
        (log/warnf "%s failed: %s" (name (p/provider-name provider)) (.getMessage e))
        []))))

(defn enrich!
  "Enrich stale vulnerabilities in the store.

  Returns `{:requested n :written n :offline? bool :providers [..]}`.

  With `:offline? true` no request is made at all and the run is a no-op,
  which is how a report is produced in an air-gapped job from whatever the
  last online run cached."
  [connectable {:keys [max-age concurrency sightings? offline? providers limit]
                :or   {concurrency 4}
                :as   opts}]
  (binding [http/*offline* (boolean offline?)]
    (let [ids (cond-> (stale-ids connectable max-age)
                limit (->> (take limit) vec))]
      (cond
        (empty? ids)
        (do (log/info "nothing to enrich: every vulnerability is within max-age")
            {:requested 0 :written 0 :offline? (boolean offline?) :providers []})

        offline?
        (do (log/infof "offline: %d vulnerabilities are stale but will not be fetched"
                       (count ids))
            {:requested (count ids) :written 0 :offline? true :providers []})

        :else
        (let [providers (or providers (default-providers
                                       {:concurrency concurrency
                                        :sightings?  sightings?}))
              results   (run-providers providers ids)
              rows      (merge-results ids results)
              written   (write/upsert-vulnerabilities! connectable rows)]
          (log/infof "enriched %d vulnerabilities" written)
          {:requested (count ids)
           :written   written
           :offline?  false
           :providers (mapv (comp name p/provider-name) providers)})))))

;; ---------------------------------------------------------------------------
;; reporting

(defn status
  "Cache coverage and age, for `bb enrich --status` and the report appendix."
  [connectable]
  (let [{:keys [n-enriched n-total oldest newest]} (q/cache-age connectable)
        n-known (count (q/vulnerability-ids connectable))]
    {:n-vulnerabilities n-known
     :n-cached          (or n-total 0)
     :n-circl-enriched  (or n-enriched 0)
     :oldest            oldest
     :newest            newest
     :n-kev             (:n (db/execute-one!
                             connectable
                             ["SELECT count(*) AS n FROM vulnerability WHERE kev"]))
     :n-with-epss       (:n (db/execute-one!
                             connectable
                             ["SELECT count(*) AS n FROM vulnerability
                               WHERE epss_score IS NOT NULL"]))}))
