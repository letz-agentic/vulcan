(ns vulcan.analysis.categorize-test
  (:require [clojure.test :refer [deftest is testing are]]
            [tablecloth.api :as tc]
            [vulcan.analysis.categorize :as cat]
            [vulcan.test-store :as ts]))

(def ^:private d cat/defaults)

(deftest exploitability-axis
  (are [expected row] (= expected (cat/exploitability d row))
    "exploited" {:kev true}
    "exploited" {:exploited true}
    "exploited" {:kev true :epss-score 0.0}
    "likely"    {:epss-score 0.1}
    "likely"    {:epss-score 0.9}
    "possible"  {:epss-score 0.01}
    "possible"  {:epss-score 0.099}
    "unlikely"  {:epss-score 0.009}
    "unlikely"  {:epss-score 0.0}
    "unlikely"  {}))

(deftest unenriched-is-unlikely-not-unknown
  (testing "the axis asks what argues for urgency; no evidence argues for none"
    (is (= "unlikely" (cat/exploitability d {:epss-score nil :kev nil})))))

(deftest thresholds-are-data
  (testing "overriding a threshold moves the boundary, and is printed in the appendix"
    (is (= "likely" (cat/exploitability (assoc d :epss-likely 0.005)
                                        {:epss-score 0.006})))))

(deftest fixability-axis
  (are [expected row] (= expected (cat/fixability row))
    "fixable"         {:status "fixed" :fixed-version "1.2.3"}
    "pending"         {:status "fixed" :fixed-version nil}
    "pending"         {:status "fixed" :fixed-version ""}
    "pending"         {:status "affected"}
    "pending"         {:status "fix_deferred"}
    "pending"         {:status "under_investigation"}
    "vendor-declined" {:status "will_not_fix"}
    "vendor-declined" {:status "end_of_life"}
    "vendor-declined" {:status "not_affected"}
    "unknown"         {:status "unknown"}
    "unknown"         {}))

(deftest vendor-declined-is-visible-not-filtered
  (testing "the unfixable backlog is exactly what management needs to see"
    (is (= "vendor-declined" (cat/fixability {:status "will_not_fix"})))))

(deftest exposure-axis
  (are [expected row] (= expected (cat/exposure row))
    "os"      {:target-class "os-pkgs"}
    "lang"    {:target-class "lang-pkgs"}
    "config"  {:target-class "config"}
    "secret"  {:target-class "secret"}
    "license" {:target-class "license"}
    "unknown" {:target-class "something-new"}
    "unknown" {}))

(deftest severity-rank-orders-worst-first
  (is (< (cat/severity-rank "CRITICAL") (cat/severity-rank "HIGH")))
  (is (< (cat/severity-rank "HIGH") (cat/severity-rank "MEDIUM")))
  (is (< (cat/severity-rank "MEDIUM") (cat/severity-rank "LOW")))
  (is (< (cat/severity-rank "LOW") (cat/severity-rank "UNKNOWN"))))

(deftest categorize-adds-every-axis
  (ts/with-store [conn]
    (let [ctx (ts/context conn)
          ds  (:findings ctx)]
      (is (pos? (tc/row-count ds)))
      (doseq [col [:exploitability :fixability :exposure :severity-rank]]
        (is (contains? (set (tc/column-names ds)) col) (str col " is a column")))
      (testing "no row is left uncategorised"
        (is (every? some? (:exploitability ds)))
        (is (every? some? (:fixability ds)))
        (is (every? some? (:exposure ds)))))))

(deftest categorize-is-idempotent
  (ts/with-store [conn]
    (let [ds  (:findings (ts/context conn))
          ds2 (cat/categorize ds)]
      (is (= (vec (:fixability ds)) (vec (:fixability ds2))))
      (is (= (tc/row-count ds) (tc/row-count ds2))))))

(deftest categorize-handles-an-empty-dataset
  (let [empty-ds (tc/dataset {:severity [] :status [] :target-class []})]
    (is (zero? (tc/row-count (cat/categorize empty-ds))))))
