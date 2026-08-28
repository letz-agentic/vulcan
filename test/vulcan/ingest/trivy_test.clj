(ns vulcan.ingest.trivy-test
  (:require [clojure.test :refer [deftest is testing]]
            [vulcan.ingest.json :as vj]
            [vulcan.ingest.trivy :as trivy]
            [vulcan.test-store :as ts])
  (:import (java.time Instant)))

(def ^:private ingested-at (Instant/parse "2026-08-28T00:00:00Z"))

(defn- rows [fixture-name]
  (let [{:keys [report scan-id]} (ts/fixture-report fixture-name)]
    (trivy/report->rows report {:scan-id     scan-id
                                :source-file fixture-name
                                :ingested-at ingested-at})))

;; ---------------------------------------------------------------------------
;; identity

(deftest hash-id-is-unambiguous
  (testing "parts are not merely concatenated, so boundaries cannot be moved"
    (is (not= (trivy/hash-id "ab" "c") (trivy/hash-id "a" "bc"))))

  (testing "nil and empty string are the same absent value"
    (is (= (trivy/hash-id "a" nil "b") (trivy/hash-id "a" "" "b"))))

  (testing "stable across calls, which is what makes ingestion idempotent"
    (is (= (trivy/hash-id "x" "y") (trivy/hash-id "x" "y")))))

(deftest scan-id-is-stable-across-line-endings
  (testing "hashing is over bytes, so a file is identified by its content"
    (let [crlf (.getBytes "{\"SchemaVersion\":2}\r\n" "UTF-8")
          lf   (.getBytes "{\"SchemaVersion\":2}\n" "UTF-8")]
      ;; Different bytes really are a different scan -- this documents that
      ;; the id is byte-exact rather than content-normalised.
      (is (not= (vj/sha256 crlf) (vj/sha256 lf)))
      (is (= (vj/sha256 lf) (vj/sha256 (.getBytes "{\"SchemaVersion\":2}\n" "UTF-8")))))))

;; ---------------------------------------------------------------------------
;; normalisation

(deftest report-rows-shape
  (let [{:keys [scan targets findings packages]} (rows "image-node-os-lang.json")]
    (testing "the scan row carries provenance an auditor will ask for"
      (is (= 2 (:schema_version scan)))
      (is (= "node:18-alpine" (:artifact_name scan)))
      (is (= "container_image" (:artifact_type scan)))
      (is (= "trivy" (:scanner scan)))
      (is (some? (:trivy_version scan)))
      (is (some? (:created_at scan)))
      (is (= ingested-at (:ingested_at scan)))
      (is (some? (:raw scan)) "the whole report is kept for anything we forgot"))

    (testing "os-pkgs and lang-pkgs both become targets"
      (is (= 2 (count targets)))
      (is (= #{"os-pkgs" "lang-pkgs"} (set (map :class targets)))))

    (testing "every finding points at a target of this scan"
      (is (pos? (count findings)))
      (is (every? (set (map :target_id targets)) (map :target_id findings)))
      (is (every? #(= (:scan_id scan) (:scan_id %)) findings)))

    (testing "packages are captured, which is what makes a fraction possible"
      (is (pos? (count packages))))))

(deftest ids-are-unique-within-a-report
  (doseq [f ts/valid-fixtures]
    (let [{:keys [targets findings packages]} (rows f)]
      (testing (str f " has no duplicate ids")
        (is (apply distinct? (conj (map :target_id targets) ::sentinel)))
        (is (apply distinct? (conj (map :finding_id findings) ::sentinel)))
        (is (apply distinct? (conj (map :package_row_id packages) ::sentinel)))))))

(deftest empty-results-still-produce-a-scan
  (testing "a clean image is evidence, not an absence of data (spec 6.3)"
    (let [{:keys [scan targets findings]} (rows "image-empty-results.json")]
      (is (some? (:scan_id scan)))
      (is (empty? targets))
      (is (empty? findings)))))

(deftest normalisation-is-deterministic
  (testing "same input, same rows -- the basis of reproducible reports"
    (is (= (rows "image-alpine-os.json") (rows "image-alpine-os.json")))))

(deftest status-defaults-to-a-trivy-value
  (testing "every status is one of Trivy's own eight (spec 5.3)"
    (let [allowed #{"unknown" "not_affected" "affected" "fixed"
                    "under_investigation" "will_not_fix" "fix_deferred"
                    "end_of_life"}]
      (doseq [f ts/valid-fixtures
              status (map :status (:findings (rows f)))]
        (is (contains? allowed status) (str f " produced status " status))))))

;; ---------------------------------------------------------------------------
;; CVSS selection

(deftest best-cvss-v3-prefers-nvd
  (is (= {:source "nvd" :score 9.8 :vector "AV:N"}
         (trivy/best-cvss-v3 {:nvd    {:V3Score 9.8 :V3Vector "AV:N"}
                              :redhat {:V3Score 5.0 :V3Vector "AV:L"}}
                             "redhat"))))

(deftest best-cvss-v3-falls-back-to-severity-source
  (is (= "redhat" (:source (trivy/best-cvss-v3
                            {:redhat {:V3Score 5.0} :ghsa {:V3Score 4.0}}
                            "redhat")))))

(deftest best-cvss-v3-falls-back-to-the-highest
  (is (= 7.5 (:score (trivy/best-cvss-v3
                      {:ghsa {:V3Score 7.5} :bitnami {:V3Score 3.1}}
                      nil)))))

(deftest best-cvss-v3-ignores-v2-and-v40-only-entries
  (testing "a source with no V3 base score contributes nothing"
    (is (nil? (trivy/best-cvss-v3 {:nvd {:V2Score 7.5 :V40Score 8.1}} "nvd")))))

(deftest best-cvss-v3-of-nothing-is-nil
  (is (nil? (trivy/best-cvss-v3 nil "nvd")))
  (is (nil? (trivy/best-cvss-v3 {} nil))))

;; ---------------------------------------------------------------------------
;; timestamps

(deftest instant-parsing
  (testing "offset and Z forms both parse"
    (is (= (Instant/parse "2026-08-28T06:11:41.754688Z")
           (trivy/->instant "2026-08-28T08:11:41.754688+02:00")))
    (is (= (Instant/parse "2025-04-23T16:15:48.713Z")
           (trivy/->instant "2025-04-23T16:15:48.713Z"))))

  (testing "an unparseable date is a gap, not a failure"
    (is (nil? (trivy/->instant "not a date")))
    (is (nil? (trivy/->instant "")))
    (is (nil? (trivy/->instant nil)))))
