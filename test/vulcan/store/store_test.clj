(ns vulcan.store.store-test
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [tablecloth.api :as tc]
            [vulcan.store.db :as db]
            [vulcan.store.migrate :as migrate]
            [vulcan.store.query :as q]
            [vulcan.test-store :as ts]))

;; ---------------------------------------------------------------------------
;; migrations

(deftest migrations-apply-in-order-and-once
  (ts/with-store [conn ts/fresh-store]
    (is (= [1 2 3] (vec (migrate/applied conn))))
    (testing "a second migrate! is a no-op"
      (is (empty? (migrate/migrate! conn)))
      (is (= [1 2 3] (vec (migrate/applied conn)))))))

(deftest migrations-record-the-engine-version
  (ts/with-store [conn ts/fresh-store]
    (let [rows (db/execute! conn ["SELECT version, duckdb_version FROM schema_migration"])]
      (is (every? #(str/starts-with? (:duckdb-version %) "v") rows)))))

(deftest jar-manifest-matches-the-resource-directory
  (testing "the jar fallback listing cannot silently drift from resources/sql"
    (let [on-disk (->> (.listFiles (io/file (io/resource "sql")))
                       (map #(.getName %))
                       (filter #(re-matches #"^\d{4}_.+\.sql$" %))
                       sort vec)
          known   (mapv (fn [{:keys [version name]}]
                          (format "%04d_%s.sql" version name))
                        (migrate/migrations))]
      (is (= on-disk known)))))

(deftest statement-splitting
  (testing "a trailing comment-only chunk is dropped, not executed as SQL"
    (is (= ["-- a comment\nSELECT 1"]
           (migrate/statements "-- a comment\nSELECT 1;\n-- trailing\n")))
    (is (empty? (migrate/statements "-- nothing but comments\n"))))

  (testing "several statements split on their terminators"
    (is (= ["SELECT 1" "SELECT 2"] (migrate/statements "SELECT 1;\nSELECT 2;\n")))))

;; ---------------------------------------------------------------------------
;; views

(deftest views-exist-and-are-queryable
  (ts/with-store [conn ts/fresh-store]
    (doseq [v ["v_finding_enriched" "v_latest_scan_per_artifact" "v_scan_summary"]]
      (is (some? (db/execute-one! conn [(str "SELECT count(*) AS n FROM " v)]))
          (str v " is queryable on an empty store")))))

(deftest latest-scan-picks-one-row-per-artifact
  (ts/with-store [conn]
    (let [latest (db/execute! conn ["SELECT artifact_name, created_at
                                     FROM v_latest_scan_per_artifact"])
          all    (db/execute! conn ["SELECT artifact_name FROM scan"])]
      (testing "one row per artifact, even though alpine:3.19 was scanned twice"
        (is (= (count (distinct (map :artifact-name all))) (count latest)))
        (is (apply distinct? (map :artifact-name latest))))

      (testing "and it is the newest one"
        (let [newest (:created-at (db/execute-one!
                                   conn ["SELECT max(created_at) AS created_at
                                          FROM scan WHERE artifact_name = 'alpine:3.19'"]))
              picked (:created-at (db/execute-one!
                                   conn ["SELECT created_at FROM v_latest_scan_per_artifact
                                          WHERE artifact_name = 'alpine:3.19'"]))]
          (is (= newest picked)))))))

(deftest enriched-view-derives-its-columns
  (ts/with-store [conn]
    (let [rows (db/execute! conn ["SELECT * FROM v_finding_enriched LIMIT 50"])]
      (is (seq rows))
      (testing "is_fixable agrees with status and fixed_version"
        (is (every? (fn [{:keys [is-fixable status fixed-version]}]
                      (= is-fixable
                         (boolean (and (= "fixed" status) (seq fixed-version)))))
                    rows)))
      (testing "exploited is false rather than null when unenriched"
        (is (every? #(false? (:exploited %)) rows))))))

(deftest scan-summary-counts-add-up
  (ts/with-store [conn]
    (doseq [{:keys [scan-id n-findings n-critical n-high n-medium n-low n-unknown]}
            (db/execute! conn ["SELECT * FROM v_scan_summary"])]
      (is (= n-findings (+ n-critical n-high n-medium n-low n-unknown))
          (str "severity counts partition the findings of scan " scan-id)))))

;; ---------------------------------------------------------------------------
;; query layer

(deftest queries-return-datasets
  (ts/with-store [conn]
    (doseq [[label ds] {"findings" (q/findings conn :latest)
                        "scans"    (q/scans conn :latest)
                        "packages" (q/packages conn :latest)
                        "summary"  (q/scan-summary conn)}]
      (is (tc/dataset? ds) (str label " is a dataset"))
      (is (pos? (tc/row-count ds)) (str label " is non-empty")))))

(deftest column-names-are-kebab-not-mangled
  (testing "cvss_v3_score must not become :cvss-v-3-score"
    (ts/with-store [conn]
      (let [cols (set (tc/column-names (q/findings conn :latest)))]
        (is (contains? cols :cvss-v3-score))
        (is (contains? cols :vulnerability-id))
        (is (not (contains? cols :cvss-v-3-score)))))))

(deftest array-columns-read-as-vectors
  (testing "no layer above the store should ever see a java.sql.Array"
    (ts/with-store [conn]
      (let [cwes (->> (db/execute! conn ["SELECT cwe_ids FROM finding
                                          WHERE cwe_ids IS NOT NULL LIMIT 5"])
                      (map :cwe-ids))]
        (is (seq cwes))
        (is (every? vector? cwes))
        (is (every? string? (flatten cwes)))))))

(deftest scopes-select-what-they-say
  (ts/with-store [conn]
    (testing ":latest is one scan per artifact"
      (let [ds (q/scans conn :latest)]
        (is (apply distinct? (:artifact-name ds)))))

    (testing "{:artifacts [..]} takes every scan of those artifacts"
      (let [ds (q/scans conn {:artifacts ["alpine:3.19"]})]
        (is (= 2 (tc/row-count ds)))
        (is (every? #(= "alpine:3.19" %) (:artifact-name ds)))))

    (testing "{:scan-ids [..]} takes exactly those"
      (let [id (first (:scan-id (q/scans conn :latest)))
            ds (q/scans conn {:scan-ids [id]})]
        (is (= 1 (tc/row-count ds)))
        (is (= id (first (:scan-id ds))))))

    (testing "an unrecognised scope is an error, not silently everything"
      (is (thrown? clojure.lang.ExceptionInfo (q/scans conn {:nonsense true}))))))

(deftest packages-query-joins-without-ambiguity
  (testing "scan_id exists on several joined relations"
    (ts/with-store [conn]
      (let [ds (q/packages conn :latest)]
        (is (pos? (tc/row-count ds)))
        (is (contains? (set (tc/column-names ds)) :artifact-name))))))

(deftest previous-scan-ids-only-for-rescanned-artifacts
  (ts/with-store [conn]
    (let [pairs (q/previous-scan-ids conn :latest)]
      (is (= ["alpine:3.19"] (keys pairs)))
      (is (not= (:current (get pairs "alpine:3.19"))
                (:previous (get pairs "alpine:3.19")))))))

(deftest cache-age-on-an-unenriched-store
  (ts/with-store [conn]
    (let [{:keys [n-enriched n-total]} (q/cache-age conn)]
      (is (zero? n-enriched))
      (is (zero? n-total)))))

(deftest vulnerability-ids-are-distinct-and-sorted
  (ts/with-store [conn]
    (let [ids (q/vulnerability-ids conn)]
      (is (seq ids))
      (is (apply distinct? ids))
      (is (= (sort ids) ids)))))

;; ---------------------------------------------------------------------------
;; the DuckDB-native escape hatch (spec 6.4)

(deftest read-json-adhoc-works
  (ts/with-store [conn ts/fresh-store]
    (let [ds (q/read-json-adhoc conn (ts/fixture-file "image-alpine-os.json"))]
      (is (= 1 (tc/row-count ds)))
      (is (contains? (set (tc/column-names ds)) :SchemaVersion)))))

(deftest read-json-adhoc-accepts-objects-over-16-mib
  (testing "the default maximum_object_size would reject a --list-all-pkgs report"
    (ts/with-store [conn ts/fresh-store]
      (let [big  (java.io.File/createTempFile "vulcan-big" ".json")
            ;; ~20 MiB: comfortably past DuckDB's 16 MiB default.
            blob  (apply str (repeat (* 20 1024 1024) \x))]
        (try
          (spit big (str "{\"SchemaVersion\": 2, \"Pad\": \"" blob "\"}"))
          (is (> (.length big) (* 16 1024 1024)))
          (let [ds (q/read-json-adhoc conn big)]
            (is (= 1 (tc/row-count ds))))
          (finally (.delete big)))))))

;; ---------------------------------------------------------------------------
;; naming

(deftest snake-to-kebab-does-not-split-digits
  (is (= :cvss-v3-score (db/snake->kebab "cvss_v3_score")))
  (is (= :scan-id (db/snake->kebab "scan_id")))
  (is (= :n (db/snake->kebab "n"))))
