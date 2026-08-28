(ns vulcan.store.query
  "Reads from the store, as tablecloth datasets (spec sections 5.4, 8.1).

  This is the only namespace that composes SQL. Everything above it receives
  datasets and never sees a connection, which is what keeps the analysis layer
  testable and the notebooks honest.

  Queries go against the *views*, not the base tables: the views are the
  contract, and changing a base column without changing a view must not break
  a notebook."
  (:require [honey.sql :as sql]
            [tablecloth.api :as tc]
            [vulcan.store.db :as db])
  (:import (java.time Instant)))

;; ---------------------------------------------------------------------------
;; ResultSet -> dataset

(defn- ->dataset
  "Run `sql-params` and return a tablecloth dataset.

  The spec (section 3) nominated `tech.ml.dataset.sql/result-set->dataset` for
  the ResultSet hop. It does not work against the DuckDB driver: it calls
  `ResultSet.getRow` to track position, and `DuckDBResultSet` throws
  `SQLFeatureNotSupportedException` for it. We therefore materialise rows
  through next.jdbc -- which is the driver-blessed path anyway -- and build the
  dataset from those.

  The cost is an intermediate row map per result row. That is acceptable at
  our scale (a scope is thousands to low millions of findings, and DuckDB has
  already done the aggregation); if it ever stops being acceptable, the honest
  fix is DuckDB's Arrow export rather than reinstating a driver-incompatible
  helper. See doc/adr/0002-resultset-to-dataset.md."
  [connectable sql-params dataset-name]
  (-> (db/execute! connectable sql-params)
      (tc/dataset {:dataset-name dataset-name})))

(defn dataset
  "Dataset from a HoneySQL map or a `[sql & params]` vector."
  ([connectable q] (dataset connectable q "query"))
  ([connectable q dataset-name]
   (->dataset connectable (if (map? q) (sql/format q) q) dataset-name)))

;; ---------------------------------------------------------------------------
;; scope (spec section 8.1)

(defn scope->where
  "Translate a scope into a HoneySQL `where` clause over `v_finding_enriched`
  (or any relation carrying `scan_id`/`artifact_name`/`scan_created_at`).

  Scopes:
    :latest              one scan per artifact, the newest (the default)
    {:artifacts [..]}    every scan of the named artifacts
    {:scan-ids [..]}     exactly these scans
    {:since inst}        every scan created at or after `inst`"
  [scope]
  (cond
    (or (nil? scope) (= :latest scope))
    [:in :scan_id {:select [:scan_id] :from [:v_latest_scan_per_artifact]}]

    (:scan-ids scope)
    [:in :scan_id (vec (:scan-ids scope))]

    (:artifacts scope)
    [:in :artifact_name (vec (:artifacts scope))]

    (:since scope)
    [:>= :scan_created_at (:since scope)]

    :else
    (throw (ex-info "Unrecognised scope" {:scope scope}))))

(defn- scan-scope->where
  "The same scope, expressed over the `scan` relation, whose timestamp column
  is `created_at` rather than `scan_created_at`.

  `alias` qualifies the column names, which a join needs: `scan_id` is
  ambiguous the moment two joined relations both carry it."
  ([scope] (scan-scope->where scope nil))
  ([scope alias]
   (let [col (fn [c] (if alias (keyword (str (name alias) "." (name c))) c))]
     (cond
       (or (nil? scope) (= :latest scope))
       [:in (col :scan_id) {:select [:scan_id] :from [:v_latest_scan_per_artifact]}]

       (:scan-ids scope)  [:in (col :scan_id) (vec (:scan-ids scope))]
       (:artifacts scope) [:in (col :artifact_name) (vec (:artifacts scope))]
       (:since scope)     [:>= (col :created_at) (:since scope)]

       :else (throw (ex-info "Unrecognised scope" {:scope scope}))))))

;; ---------------------------------------------------------------------------
;; the queries the analysis layer is allowed to ask for

(defn scans
  "Scans in scope."
  [connectable scope]
  (dataset connectable
           {:select [:*] :from [:scan] :where (scan-scope->where scope)
            :order-by [[:created_at :desc] [:artifact_name :asc]]}
           "scans"))

(defn findings
  "Enriched findings in scope: the fact table joined to its dimensions, with
  `is_fixable`, `age_days`, `exploited` and any active decision already
  resolved by the view."
  [connectable scope]
  (dataset connectable
           {:select [:*] :from [:v_finding_enriched] :where (scope->where scope)}
           "findings"))

(defn packages
  "Packages in scope. Empty unless scans were run with `--list-all-pkgs`."
  [connectable scope]
  (dataset connectable
           {:select   [:p.* :s.artifact-name :t.class :t.type]
            :from     [[:package :p]]
            :join     [[:scan :s]   [:= :s.scan-id :p.scan-id]
                       [:target :t] [:= :t.target-id :p.target-id]]
            :where    (scan-scope->where scope :s)}
           "packages"))

(defn scan-summary
  "Per-scan counts by severity and status, over *all* scans, not just those in
  scope: a trend line that only shows the current scope is not a trend."
  [connectable]
  (dataset connectable
           {:select [:*] :from [:v_scan_summary] :order-by [[:created_at :asc]]}
           "scan-summary"))

(defn previous-scan-ids
  "For each artifact with a scan in scope, the scan immediately preceding it.
  Returns `{artifact-name {:current id :previous id}}`, omitting artifacts
  that have only ever been scanned once."
  [connectable scope]
  (let [rows (db/execute!
              connectable
              (sql/format
               {:select   [:artifact-name :scan-id :created-at
                           [[:over [[:lag :scan-id]
                                    {:partition-by [:artifact-name]
                                     :order-by     [[:created-at :asc]]}]]
                            :prev-scan-id]]
                :from     [:scan]}))
        in-scope (into #{} (map :scan-id)
                       (db/execute! connectable
                                    (sql/format {:select [:scan-id] :from [:scan]
                                                 :where  (scan-scope->where scope)})))]
    (into {}
          (for [{:keys [artifact-name scan-id prev-scan-id]} rows
                :when (and (in-scope scan-id) prev-scan-id)]
            [artifact-name {:current scan-id :previous prev-scan-id}]))))

(defn vulnerability-ids
  "Distinct vulnerability ids present in the store, optionally only those whose
  enrichment is missing or older than `max-age` (spec section 7.2)."
  ([connectable] (vulnerability-ids connectable nil))
  ([connectable ^Instant stale-before]
   (mapv :vulnerability-id
         (db/execute!
          connectable
          (sql/format
           {:select-distinct [:f.vulnerability-id]
            :from            [[:finding :f]]
            :left-join       [[:vulnerability :v] [:= :v.vulnerability-id :f.vulnerability-id]]
            :where           (if stale-before
                               [:or
                                [:= :v.vulnerability-id nil]
                                [:= :v.circl-fetched-at nil]
                                [:< :v.circl-fetched-at stale-before]]
                               true)
            :order-by        [[:f.vulnerability-id :asc]]})))))

(defn cache-age
  "Age of the enrichment cache as `{:oldest inst :newest inst :n-enriched n
  :n-total n}`. Every report is stamped with this (spec sections 7.2, 10.1)."
  [connectable]
  (let [row (db/execute-one!
             connectable
             ["SELECT min(circl_fetched_at) AS oldest,
                      max(circl_fetched_at) AS newest,
                      count(circl_fetched_at) AS n_enriched,
                      count(epss_score) AS n_with_epss,
                      count(*) FILTER (kev) AS n_kev,
                      count(*) AS n_total
                 FROM vulnerability"])]
    (or row {:oldest nil :newest nil :n-enriched 0 :n-total 0
             :n-with-epss 0 :n-kev 0})))

;; ---------------------------------------------------------------------------
;; escape hatch (spec section 6.4)

(defn read-json-adhoc
  "Read a Trivy report straight into DuckDB with `read_json`, for one-off
  exploration.

  This is deliberately *not* the ingestion path: validation, schema-version
  handling and unit testing are all markedly easier on Clojure maps. It exists
  because the option is free (the `raw` column already holds the JSON) and
  because it is the likely optimisation if ingest throughput ever matters.

  `maximum_object_size` is set explicitly because DuckDB defaults to 16 MiB
  and a `--list-all-pkgs` report over a large image exceeds that."
  ([connectable path] (read-json-adhoc connectable path {}))
  ([connectable path {:keys [max-object-size] :or {max-object-size 268435456}}]
   (dataset connectable
            [(format "SELECT * FROM read_json(?, maximum_object_size = %d)"
                     (long max-object-size))
             (str path)]
            "read-json-adhoc")))
