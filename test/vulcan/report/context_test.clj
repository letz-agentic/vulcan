(ns vulcan.report.context-test
  (:require [clojure.test :refer [deftest is testing]]
            [tablecloth.api :as tc]
            [vulcan.analysis.core :as core]
            [vulcan.report.context :as ctx]
            [vulcan.test-store :as ts]))

(deftest context-has-every-promised-key
  (testing "the contract notebooks are written against (spec 8.1)"
    (ts/with-store [conn]
      (let [c (ts/context conn)]
        (doseq [k [:meta :scans :findings :packages :summary :scored
                   :by-package :diff :trend]]
          (is (contains? c k) (str k " is present")))))))

(deftest meta-carries-the-provenance-an-auditor-asks-for
  (ts/with-store [conn]
    (let [m (:meta (ts/context conn))]
      (is (seq (:scan-ids m)) "a report is reproducible from its scan ids")
      (is (some? (:generated-at m)))
      (is (some? (:duckdb m)))
      (is (= :latest (:scope m)))
      (testing "thresholds and weights are stamped, so a ranking can be re-derived"
        (is (some? (get-in m [:thresholds :epss-likely])))
        (is (> 1e-9 (abs (- 1.0 (reduce + (vals (:weights m)))))))))))

(deftest summary-numbers-agree-with-the-datasets
  (testing "prose interpolates from :summary, so it must match the charts (spec 10.1)"
    (ts/with-store [conn]
      (let [{:keys [summary findings scans]} (ts/context conn)]
        (is (= (tc/row-count findings) (:n-findings summary)))
        (is (= (tc/row-count scans) (:n-scans summary)))
        (is (= (-> findings :vulnerability-id distinct count) (:n-vulns summary)))
        (testing "severity counts partition the findings"
          (is (= (:n-findings summary)
                 (+ (:n-critical summary) (:n-high summary) (:n-medium summary)
                    (:n-low summary) (:n-unknown summary)))))
        (testing "fixable and declined are counted from the categorised column"
          (is (= (count (filter #(= "fixable" %) (:fixability findings)))
                 (:n-fixable summary))))))))

(deftest scoring-orders-worst-first
  (ts/with-store [conn]
    (let [scores (vec (:fix-first-score (:scored (ts/context conn))))]
      (is (seq scores))
      (is (= scores (vec (reverse (sort scores))))))))

(deftest by-package-columns-are-not-index-suffixed
  (testing "aggregators must return scalars, or tablecloth splits them into columns"
    (ts/with-store [conn]
      (let [cols (set (tc/column-names (:by-package (ts/context conn))))]
        (is (contains? cols :artifacts))
        (is (contains? cols :vulnerabilities))
        (is (contains? cols :worst-severity))
        (is (not-any? #(re-find #"-\d+$" (name %)) cols))))))

(deftest by-package-totals-agree-with-the-findings
  (ts/with-store [conn]
    (let [{:keys [scored by-package]} (ts/context conn)]
      (is (= (tc/row-count scored) (reduce + (:n-findings by-package)))
          "every scored finding belongs to exactly one package group"))))

(deftest scope-changes-what-is-in-the-context
  (ts/with-store [conn]
    (let [all-latest (ts/context conn :latest)
          just-one   (ts/context conn {:artifacts ["alpine:3.19"]})]
      (is (> (tc/row-count (:findings all-latest))
             (tc/row-count (:findings just-one))))
      (is (every? #(= "alpine:3.19" %) (:artifact-name (:findings just-one)))))))

(deftest trend-covers-every-scan-not-just-the-scope
  (testing "a trend line restricted to the current scope is not a trend"
    (ts/with-store [conn]
      (let [c (ts/context conn {:artifacts ["alpine:3.19"]})]
        (is (> (-> c :trend :scan-id distinct count)
               (count (get-in c [:meta :scan-ids]))))))))

(deftest an-empty-scope-produces-an-empty-but-usable-context
  (testing "a report over nothing must render, not throw"
    (ts/with-store [conn ts/fresh-store]
      (let [c (ts/context conn)]
        (is (zero? (tc/row-count (:findings c))))
        (is (zero? (:n-findings (:summary c))))
        (is (nil? (:pct-packages-affected (:summary c)))
            "a fraction with no denominator is nil, not zero or NaN")
        (is (zero? (tc/row-count (:diff c))))))))

(deftest percentage-affected-needs-a-denominator
  (ts/with-store [conn]
    (let [{:keys [summary]} (ts/context conn)]
      (is (pos? (:n-packages summary)) "fixtures were scanned with --list-all-pkgs")
      (is (some? (:pct-packages-affected summary)))
      (is (<= 0.0 (:pct-packages-affected summary) 100.0)))))

(deftest top-findings-is-a-chosen-subset
  (ts/with-store [conn]
    (let [t (core/top-findings (:scored (ts/context conn)) 5)]
      (is (= 5 (tc/row-count t)))
      (is (not (contains? (set (tc/column-names t)) :raw))))))

(deftest severity-counts-include-zeroes
  (testing "a missing bar reads as 'not measured', which is the wrong message"
    (ts/with-store [conn ts/fresh-store]
      (let [sc (core/severity-counts (:findings (ts/context conn)))]
        (is (= 5 (tc/row-count sc)))
        (is (every? zero? (:n sc)))))))

(deftest config-precedence
  (testing "explicit overrides beat defaults"
    (is (= "explicit.duckdb" (:db (ctx/config {:db "explicit.duckdb"}))))
    (is (= :latest (:scope (ctx/config {}))))
    (is (= :html (:profile (ctx/config {}))))))
