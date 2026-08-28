(ns vulcan.store.write
  "Batched, idempotent writes into the canonical store (spec sections 5.1, 6.2).

  Every insert is `ON CONFLICT DO NOTHING` against a content-derived primary
  key, so the store is append-only and re-ingesting a file changes nothing.
  That is what makes two independently built stores mergeable and every report
  reproducible by `scan_id`."
  (:require [clojure.string :as str]
            [next.jdbc :as jdbc]
            [next.jdbc.prepare :as prep]
            [vulcan.store.db :as db])
  (:import (java.sql Connection PreparedStatement)
           (java.time Instant)))

(def ^:private table-columns
  "Column order per table. Explicit rather than derived from the row maps, so
  a normaliser that starts emitting a new key fails loudly at the schema
  instead of silently writing into the wrong column."
  {:scan    [:scan_id :schema_version :created_at :ingested_at :artifact_name
             :artifact_type :image_id :repo_digests :os_family :os_name
             :os_eosl :trivy_version :source_file :raw :scanner]
   :target  [:target_id :scan_id :target :class :type]
   :finding [:finding_id :scan_id :target_id :vulnerability_id :pkg_id
             :pkg_name :purl :installed_version :fixed_version :status
             :severity :severity_source :cvss :cvss_v3_score :cvss_v3_vector
             :cwe_ids :published_date :last_modified_date :layer_digest
             :layer_diff_id :data_source :title :refs :scanner_native]
   :package [:package_row_id :scan_id :target_id :pkg_id :pkg_name :version
             :release :epoch :arch :purl :licenses :indirect :layer_digest]})

(def ^:private json-columns
  "Columns declared JSON in the DDL. DuckDB's JDBC driver will not implicitly
  widen a VARCHAR parameter into JSON, so these are cast at the placeholder."
  #{:raw :cvss :data_source :circl_raw :scanner_native})

(def ^:private array-columns
  "Columns declared `VARCHAR[]`. Bound as a JDBC array, not a string."
  #{:repo_digests :cwe_ids :refs :licenses})

(defn- placeholder [col]
  (cond
    (json-columns col)  "CAST(? AS JSON)"
    (array-columns col) "?"
    :else               "?"))

(defn insert-sql
  "`INSERT ... ON CONFLICT DO NOTHING` for `table` over `cols`."
  [table cols]
  (format "INSERT INTO %s (%s) VALUES (%s) ON CONFLICT DO NOTHING"
          (name table)
          (str/join ", " (map name cols))
          (str/join ", " (map placeholder cols))))

(defn- bind-value
  "Coerce a Clojure value into something the DuckDB driver accepts.

  This is the only place a row map stops being pure data: array columns arrive
  as Clojure vectors (so that rows stay comparable and EDN-serialisable) and
  become JDBC arrays here."
  [^Connection conn col v]
  (cond
    (nil? v)              nil
    (array-columns col)   (.createArrayOf conn "VARCHAR" (into-array String (map str v)))
    (instance? Instant v) (java.sql.Timestamp/from ^Instant v)
    :else                 v))

(defn insert-batch!
  "Insert `rows` into `table` in one prepared batch. Returns the number of rows
  offered (not the number actually stored: conflicts are silently skipped, and
  that is the point)."
  [connectable table rows]
  (if (empty? rows)
    0
    (let [cols (get table-columns table)
          sql  (insert-sql table cols)]
      (db/with-connection [conn connectable]
        (with-open [^PreparedStatement ps (.prepareStatement ^Connection conn sql)]
          (doseq [row rows]
            (prep/set-parameters ps (mapv #(bind-value conn % (get row %)) cols))
            (.addBatch ps))
          (.executeBatch ps)))
      (count rows))))

(defn scan-exists?
  "Has this exact report already been ingested? The check is on the
  content-derived `scan_id`, so it is a byte-level duplicate check."
  [connectable scan-id]
  (some? (db/execute-one! connectable
                          ["SELECT scan_id FROM scan WHERE scan_id = ?" scan-id])))

(defn log-ingest!
  [connectable {:keys [scan-id source-file outcome message]}]
  (db/execute! connectable
               ["INSERT INTO ingest_log (scan_id, source_file, ingested_at, outcome, message)
                 VALUES (?, ?, now(), ?, ?)"
                scan-id source-file (name outcome) message]))

(defn write-rows!
  "Persist one normalised report in a single transaction (spec section 6.2).
  Returns `{:scan-id :inserted {:targets n :findings n :packages n}}`."
  [connectable {:keys [scan targets findings packages]}]
  (jdbc/with-transaction [tx connectable]
    (insert-batch! tx :scan    [scan])
    (insert-batch! tx :target  targets)
    (insert-batch! tx :finding findings)
    (insert-batch! tx :package packages)
    {:scan-id  (:scan_id scan)
     :inserted {:targets  (count targets)
                :findings (count findings)
                :packages (count packages)}}))
