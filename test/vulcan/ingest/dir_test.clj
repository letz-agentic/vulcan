(ns vulcan.ingest.dir-test
  (:require [clojure.test :refer [deftest is testing]]
            [vulcan.ingest.dir :as ing]
            [vulcan.store.db :as db]
            [vulcan.test-store :as ts]))

(defn- table-counts [conn]
  (into {} (for [t ["scan" "target" "finding" "package"]]
             [t (:n (db/execute-one! conn [(str "SELECT count(*) AS n FROM " t)]))])))

(deftest ingesting-a-directory
  (ts/with-store [conn ts/fresh-store]
    (let [{:keys [counts]} (ing/ingest! conn [ts/fixture-dir] {})]
      (testing "valid fixtures land, rejection fixtures do not"
        (is (= (count ts/valid-fixtures) (:inserted counts)))
        (is (= 2 (:rejected counts)) "reject-schema-v1 and reject-malformed")
        (is (zero? (:duplicate counts)))))))

(deftest ingestion-is-idempotent
  (testing "re-ingesting the same reports changes nothing (spec 5.1)"
    (ts/with-store [conn ts/fresh-store]
      (ing/ingest! conn [ts/fixture-dir] {})
      (let [after-first (table-counts conn)
            {:keys [counts]} (ing/ingest! conn [ts/fixture-dir] {})
            after-second (table-counts conn)]
        (is (= (count ts/valid-fixtures) (:duplicate counts)))
        (is (zero? (:inserted counts)))
        (is (= after-first after-second)
            "row counts are byte-identical after a second pass")))))

(deftest schema-version-1-is-rejected-by-name
  (testing "the message names the version, because that is what a user can act on"
    (ts/with-store [conn ts/fresh-store]
      (let [r (ing/ingest-file! conn (ts/fixture-file "reject-schema-v1.json") {})]
        (is (= :rejected (:outcome r)))
        (is (= :unsupported-schema-version (:reason r)))
        (is (re-find #"SchemaVersion 1" (:message r)))))))

(deftest malformed-json-is-rejected-not-fatal
  (ts/with-store [conn ts/fresh-store]
    (let [r (ing/ingest-file! conn (ts/fixture-file "reject-malformed.json") {})]
      (is (= :rejected (:outcome r)))
      (testing "and the store is still usable afterwards"
        (is (= :inserted (:outcome (ing/ingest-file!
                                    conn (ts/fixture-file "image-alpine-os.json") {}))))))))

(deftest one-bad-file-does-not-stop-the-run
  (testing "failure policy is per-file (spec 6.3)"
    (ts/with-store [conn ts/fresh-store]
      (let [{:keys [counts]} (ing/ingest! conn [ts/fixture-dir] {})]
        (is (pos? (:inserted counts)))
        (is (pos? (:rejected counts)))))))

(deftest empty-results-is-recorded-as-a-scan
  (ts/with-store [conn ts/fresh-store]
    (ing/ingest-file! conn (ts/fixture-file "image-empty-results.json") {})
    (is (= 1 (:n (db/execute-one! conn ["SELECT count(*) AS n FROM scan"]))))
    (is (zero? (:n (db/execute-one! conn ["SELECT count(*) AS n FROM finding"]))))))

(deftest dry-run-writes-nothing
  (ts/with-store [conn ts/fresh-store]
    (let [{:keys [counts]} (ing/ingest! conn [ts/fixture-dir] {:dry-run? true})]
      (is (pos? (:inserted counts)) "it still reports what it would insert")
      (is (= {"scan" 0 "target" 0 "finding" 0 "package" 0} (table-counts conn)))
      (is (zero? (:n (db/execute-one! conn ["SELECT count(*) AS n FROM ingest_log"])))))))

(deftest every-outcome-is-logged
  (ts/with-store [conn ts/fresh-store]
    (ing/ingest! conn [ts/fixture-dir] {})
    (let [by-outcome (into {} (map (juxt :outcome :n))
                           (db/execute! conn ["SELECT outcome, count(*) AS n
                                               FROM ingest_log GROUP BY 1"]))]
      (is (= (count ts/valid-fixtures) (get by-outcome "inserted")))
      (is (= 2 (get by-outcome "rejected"))))))

(deftest json-files-discovery
  (testing "a directory is walked recursively and sorted"
    (let [fs (ing/json-files ts/fixture-dir)]
      (is (every? #(.endsWith (.getName %) ".json") fs))
      (is (= (sort (map #(.getPath %) fs)) (map #(.getPath %) fs)))))

  (testing "a single file is taken as-is"
    (is (= 1 (count (ing/json-files (ts/fixture-file "image-alpine-os.json"))))))

  (testing "a missing path is an error, not an empty run"
    (is (thrown? clojure.lang.ExceptionInfo (ing/json-files "no/such/dir")))))
