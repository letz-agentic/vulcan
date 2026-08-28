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
  (:import (java.sql Connection PreparedStatement)))

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

  Only arrays need handling here: they are the one case that needs a live
  Connection to build. `java.time` values are bound by the `SettableParameter`
  extension in `vulcan.store.db`, which covers queries as well as inserts.

  This is the only place a row map stops being pure data: array columns arrive
  as Clojure vectors, so rows stay comparable and EDN-serialisable, and become
  JDBC arrays at the last moment."
  [^Connection conn col v]
  (if (and (some? v) (array-columns col))
    (.createArrayOf conn "VARCHAR" (into-array String (map str v)))
    v))

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

;; ---------------------------------------------------------------------------
;; enrichment and decisions (spec sections 7.2, 7.3)
;;
;; These upsert rather than `DO NOTHING`. The findings tables are append-only
;; because a scan is a historical fact; enrichment is the opposite -- a
;; refreshed EPSS score is meant to replace the stale one, and that is the
;; whole point of `--max-age`.

(def ^:private vulnerability-columns
  [:vulnerability_id :description :epss_score :epss_percentile :epss_date
   :kev :kev_date_added :kev_ransomware :sightings_count
   :circl_fetched_at :circl_raw])

(def ^:private decision-columns
  [:decision_id :vulnerability_id :scope :status :justification :note
   :decided_by :decided_at :expires_at :source])

(defn- upsert-sql
  "`INSERT ... ON CONFLICT (pk) DO UPDATE`, updating only the columns this row
  actually carries a value for.

  `COALESCE(excluded.c, table.c)` is what makes partial enrichment safe: a run
  that fetched KEV but could not reach CIRCL must refresh `kev` without
  blanking the description it already had."
  [table pk cols]
  (format "INSERT INTO %s (%s) VALUES (%s)
           ON CONFLICT (%s) DO UPDATE SET %s"
          (name table)
          (str/join ", " (map name cols))
          (str/join ", " (map placeholder cols))
          (name pk)
          (str/join ", " (for [c cols :when (not= c pk)]
                           (format "%s = COALESCE(excluded.%s, %s.%s)"
                                   (name c) (name c) (name table) (name c))))))

(defn- upsert-batch!
  [connectable table pk cols rows]
  (if (empty? rows)
    0
    (let [sql (upsert-sql table pk cols)]
      (db/with-connection [conn connectable]
        (with-open [^PreparedStatement ps (.prepareStatement ^Connection conn sql)]
          (doseq [row rows]
            (prep/set-parameters ps (mapv #(bind-value conn % (get row %)) cols))
            (.addBatch ps))
          (.executeBatch ps)))
      (count rows))))

(defn- kebab->snake
  "Providers and the VEX importer speak kebab-case, the columns are snake_case."
  [row]
  (into {} (map (fn [[k v]] [(keyword (str/replace (name k) "-" "_")) v])) row))

(defn upsert-vulnerabilities!
  "Write enrichment rows, refreshing what is present and preserving what is
  not. Accepts kebab-case keys, as the providers produce them."
  [connectable rows]
  (upsert-batch! connectable :vulnerability :vulnerability_id
                 vulnerability-columns (map kebab->snake rows)))

(defn upsert-decisions!
  "Write VEX-derived decisions (spec section 7.3)."
  [connectable rows]
  (upsert-batch! connectable :decision :decision_id
                 decision-columns (map kebab->snake rows)))

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
