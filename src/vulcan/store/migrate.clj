(ns vulcan.store.migrate
  "Ordered SQL migrations from `resources/sql/NNNN_*.sql` (spec §5.5).

  Each file is applied once, in numeric order, inside a transaction, and
  recorded in `schema_migration` together with the DuckDB version that applied
  it. DuckDB's storage format has changed across major versions, so we refuse
  to touch a store written by a newer engine than the driver we loaded."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.tools.logging :as log]
            [next.jdbc :as jdbc]
            [vulcan.store.db :as db]))

(def ^:private migration-re #"^(\d{4})_(.+)\.sql$")

(def ^:private jar-manifest
  "Fallback listing for when we run from a jar and cannot list the resource
  directory. Keep in sync with `resources/sql/`; `migrations-manifest-test`
  fails the build if it drifts."
  ["0001_init.sql" "0002_scanner.sql" "0003_views.sql"])

(defn- resource-listing []
  (let [url (io/resource "sql")]
    (if (and url (= "file" (.getProtocol url)))
      (->> (.listFiles (io/file url))
           (map #(.getName %))
           (filter #(re-matches migration-re %))
           sort
           vec)
      jar-manifest)))

(defn migrations
  "All known migrations as `{:version :name :sql}`, ordered by version."
  []
  (->> (resource-listing)
       (keep (fn [file-name]
               (when-let [[_ v nm] (re-matches migration-re file-name)]
                 {:version (parse-long v)
                  :name    nm
                  :sql     (slurp (io/resource (str "sql/" file-name)))})))
       (sort-by :version)
       vec))

(defn- comment-only? [s]
  (every? (fn [line]
            (let [t (str/trim line)]
              (or (str/blank? t) (str/starts-with? t "--"))))
          (str/split-lines s)))

(defn statements
  "Split a migration file into executable statements. Migrations use plain
  `;`-terminated DDL and deliberately never put `;` inside a string literal."
  [sql]
  (->> (str/split sql #";\s*(?:\n|$)")
       (map str/trim)
       (remove str/blank?)
       (remove comment-only?)))

(defn- ensure-migration-table! [conn]
  (db/execute! conn ["CREATE TABLE IF NOT EXISTS schema_migration (
                        version        INTEGER PRIMARY KEY,
                        name           VARCHAR NOT NULL,
                        applied_at     TIMESTAMP NOT NULL,
                        duckdb_version VARCHAR NOT NULL)"]))

(defn applied
  "Set of migration versions already applied to this store."
  [conn]
  (ensure-migration-table! conn)
  (into (sorted-set)
        (map :version)
        (db/execute! conn ["SELECT version FROM schema_migration ORDER BY version"])))

(defn- check-engine-compat!
  "Refuse to operate on a store written by a newer DuckDB than ours. Returns
  the engine version string."
  [conn]
  (let [engine   (db/duckdb-version conn)
        recorded (-> (db/execute! conn ["SELECT duckdb_version FROM schema_migration
                                         ORDER BY version DESC LIMIT 1"])
                     first :duckdb-version)]
    (when (and recorded (pos? (compare recorded engine)))
      (throw (ex-info "Store was written by a newer DuckDB than the loaded driver"
                      {:store-duckdb-version  recorded
                       :driver-duckdb-version engine})))
    engine))

(defn migrate!
  "Apply every pending migration. Returns the versions applied, in order."
  [conn]
  (let [done   (applied conn)
        engine (check-engine-compat! conn)
        todo   (remove #(contains? done (:version %)) (migrations))]
    (doseq [{:keys [version name sql]} todo]
      (log/infof "applying migration %04d_%s" version name)
      (jdbc/with-transaction [tx conn]
        (doseq [stmt (statements sql)]
          (jdbc/execute! tx [stmt]))
        (jdbc/execute! tx ["INSERT INTO schema_migration
                              (version, name, applied_at, duckdb_version)
                            VALUES (?, ?, now(), ?)"
                           version name engine])))
    (mapv :version todo)))

(defn open!
  "Bring a store fully up to date and return its connectable. Accepts a file
  path (opens a datasource) or an already-open connectable."
  [path-or-connectable]
  (let [conn (if (string? path-or-connectable)
               (db/datasource path-or-connectable)
               path-or-connectable)]
    (migrate! conn)
    conn))
