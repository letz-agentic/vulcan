(ns vulcan.test-store
  "Shared test fixtures: a migrated in-memory store loaded from
  `resources/fixtures/trivy/`.

  Tests run against the *real* fixture reports rather than hand-written maps,
  because the Trivy JSON schema has no formal published definition (spec
  section 6.1) and our reading of the docs is not the contract -- the scanner's
  actual output is."
  (:require [clojure.java.io :as io]
            [vulcan.ingest.dir :as ing]
            [vulcan.ingest.json :as vj]
            [vulcan.report.context :as ctx]
            [vulcan.store.db :as db]
            [vulcan.store.migrate :as migrate]))

(def fixture-dir "resources/fixtures/trivy")

(defn fixture-file [n] (io/file fixture-dir n))

(defn fixture-report
  "A parsed fixture report, with the scan-id the ingester would compute."
  [n]
  (let [bytes (vj/read-bytes (fixture-file n))]
    {:bytes   bytes
     :scan-id (vj/sha256 bytes)
     :report  (vj/parse bytes)}))

(def valid-fixtures
  "Fixtures the ingester is expected to accept."
  ["image-alpine-os.json"
   "image-alpine-os-later.json"
   "image-node-os-lang.json"
   "image-debian-os-lang.json"
   "image-empty-results.json"])

(defn fresh-store
  "A migrated, empty in-memory store. Callers must `db/close!` it."
  []
  (migrate/open! (db/memory-connection)))

(defn loaded-store
  "A migrated in-memory store with every valid fixture ingested."
  []
  (let [conn (fresh-store)]
    (ing/ingest! conn (map fixture-file valid-fixtures) {})
    conn))

(defmacro with-store
  "Bind `sym` to a store built by `build-fn` (default `loaded-store`), run
  `body`, and close it."
  {:clj-kondo/lint-as 'clojure.core/let}
  [[sym & [build-fn]] & body]
  `(let [~sym (~(or build-fn `loaded-store))]
     (try ~@body
          (finally (db/close! ~sym)))))

(defn context
  "A report context over a loaded store, for the analysis and viz tests."
  ([conn] (context conn :latest))
  ([conn scope] (ctx/build {:connectable conn :scope scope})))
