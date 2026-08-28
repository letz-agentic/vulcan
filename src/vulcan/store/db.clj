(ns vulcan.store.db
  "Connection management for the canonical DuckDB store (spec §3, §5).

  Everything Vulcan V knows lives in one DuckDB file. This namespace owns the
  connectable and nothing else: no DDL (that is `vulcan.store.migrate`), no
  queries (`vulcan.store.query`), no writes (`vulcan.store.write`).

  The rest of the codebase passes around a *connectable* — either a
  `javax.sql.DataSource` over a file, or a single live `java.sql.Connection`
  for an in-memory store. Both satisfy next.jdbc's protocols, so callers do
  not care which they hold."
  (:require [clojure.java.io :as io]
            [next.jdbc :as jdbc]
            [next.jdbc.result-set :as rs])
  (:import (java.sql Connection)))

(def default-db-path "data/vulcan.duckdb")

(defn snake->kebab
  "`cvss_v3_score` -> `:cvss-v3-score`.

  Deliberately *not* camel-snake-kebab's `->kebab-case`, which also splits on
  digit boundaries and would give `:cvss-v-3-score`. Our column names are
  already snake_case by construction, so swapping the separator is both
  sufficient and lossless -- and it keeps SQL column names and dataset column
  names mechanically derivable from each other in both directions."
  [^String s]
  (keyword (.replace s \_ \-)))

(def opts
  "Result-set options used everywhere: unqualified kebab-case keyword keys,
  because the analysis layer turns these straight into dataset columns."
  {:builder-fn   rs/as-unqualified-modified-maps
   :label-fn     snake->kebab
   :qualifier-fn (constantly nil)})

;; DuckDB returns `VARCHAR[]` columns as `java.sql.Array`. Reading them as
;; vectors here means no layer above the store ever handles a JDBC array --
;; `cwe_ids` and `refs` behave like any other Clojure collection.
(extend-protocol rs/ReadableColumn
  java.sql.Array
  (read-column-by-label [^java.sql.Array v _] (vec (.getArray v)))
  (read-column-by-index [^java.sql.Array v _ _] (vec (.getArray v))))

(defn spec
  "JDBC spec for a DuckDB file path."
  [path]
  {:jdbcUrl (str "jdbc:duckdb:" path)})

(defn datasource
  "Open a datasource over the file at `path`, creating parent directories if
  needed. DuckDB allows a single writer process per file, so a run should hold
  one of these and share it."
  [path]
  (io/make-parents path)
  (jdbc/get-datasource (spec path)))

(defn memory-connection
  "A live connection to a private in-memory store.

  This is deliberately a `Connection` and not a `DataSource`: DuckDB's JDBC
  driver hands every connection to an in-memory URL its *own* database, so a
  datasource over `jdbc:duckdb:` would forget the schema between calls. Tests
  and REPL scratch work use this; anything durable uses `datasource`."
  ^Connection []
  (jdbc/get-connection (jdbc/get-datasource {:jdbcUrl "jdbc:duckdb:"})))

(defn close!
  "Close a connectable if it is something closeable (an in-memory connection).
  Datasources over files need no closing."
  [connectable]
  (when (instance? java.lang.AutoCloseable connectable)
    (.close ^java.lang.AutoCloseable connectable)))

(defmacro with-connection
  "Bind `sym` to a `java.sql.Connection` for `connectable` and run `body`.

  When the connectable *is* a connection (the in-memory case) it is borrowed,
  not closed: closing it would destroy the whole database. When it is a
  datasource, a connection is opened and closed around the body."
  [[sym connectable] & body]
  `(let [c# ~connectable]
     (if (instance? Connection c#)
       (let [~sym ^Connection c#] ~@body)
       (with-open [~sym (jdbc/get-connection c#)] ~@body))))

(defn execute!
  ([connectable sql-params] (jdbc/execute! connectable sql-params opts))
  ([connectable sql-params more] (jdbc/execute! connectable sql-params (merge opts more))))

(defn execute-one!
  ([connectable sql-params] (jdbc/execute-one! connectable sql-params opts))
  ([connectable sql-params more] (jdbc/execute-one! connectable sql-params (merge opts more))))

(defn duckdb-version
  "Version string of the running DuckDB engine."
  [connectable]
  (:version (execute-one! connectable ["SELECT version() AS version"])))
