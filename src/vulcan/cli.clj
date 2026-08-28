(ns vulcan.cli
  "Command line entry point (spec section 11).

  Every `bb` task delegates here, so the same code path is available at the
  REPL as `(vulcan.cli/-main \"ingest\" \"reports/\")`. That is not a
  convenience: it means the thing CI runs and the thing you debug are the same
  function."
  (:require [clojure.edn :as edn]
            [clojure.pprint :as pp]
            [clojure.string :as str]
            [clojure.tools.cli :as cli]
            [vulcan.enrich.cache :as enrich]
            [vulcan.enrich.vex :as vex]
            [vulcan.ingest.dir :as ingest]
            [vulcan.report.context :as ctx]
            [vulcan.report.render :as render]
            [vulcan.store.db :as db]
            [vulcan.store.migrate :as migrate]
            [vulcan.viz.static :as static])
  (:gen-class))

(def common-options
  [["-d" "--db PATH" "DuckDB store path" :default nil]
   [nil "--scope EDN" "Scope: :latest, {:artifacts [..]}, {:scan-ids [..]}, {:since inst}"
    :parse-fn edn/read-string]
   ["-h" "--help"]])

(def ingest-options
  (into common-options
        [[nil "--dry-run" "Parse and validate only; write nothing"]]))

(def enrich-options
  (into common-options
        [[nil "--max-age DURATION" "Only refresh entries older than this (e.g. 7d, 12h)"
          :default "7d"]
         [nil "--concurrency N" "Requests in flight (default 4)"
          :default 4 :parse-fn parse-long]
         [nil "--sightings" "Also fetch CIRCL sighting counts (one extra request per id)"]
         [nil "--offline" "Make no requests; report what would be refreshed"]
         [nil "--limit N" "Enrich at most N vulnerabilities" :parse-fn parse-long]
         [nil "--status" "Print cache coverage and age, then exit"]]))

(def render-options
  (into common-options
        [["-p" "--profile NAME" "html | revealjs | pptx | pdf"
          :default :html :parse-fn keyword]
         [nil "--all" "Every notebook under notebooks/"]
         ["-o" "--out PATH" "Target directory"]]))

(def report-options
  (into common-options
        [[nil "--notebooks NAMES" "Comma-separated notebook names"
          :parse-fn #(str/split % #",")]
         [nil "--profiles NAMES" "Comma-separated profile names"
          :parse-fn #(mapv keyword (str/split % #","))]
         ["-o" "--out PATH" "Target directory"]]))

;; ---------------------------------------------------------------------------

(defn- open-store
  "Open and migrate the configured store."
  [{:keys [db]}]
  (migrate/open! (or db (:db (ctx/config {})))))

(defn- report-line [& parts]
  (println (str/join " " (map str parts))))

;; ---------------------------------------------------------------------------
;; tasks

(defn cmd-migrate [args]
  (let [{:keys [options]} (cli/parse-opts args common-options)
        conn (open-store options)]
    (report-line "store" (or (:db options) (:db (ctx/config {})))
                 "at DuckDB" (db/duckdb-version conn))
    (report-line "migrations applied:" (vec (migrate/applied conn)))
    0))

(defn cmd-ingest [args]
  (let [{:keys [options arguments]} (cli/parse-opts args ingest-options)
        paths (or (seq arguments) ["reports"])
        conn  (open-store options)
        {:keys [counts totals]} (ingest/ingest! conn paths
                                                {:dry-run? (:dry-run options)})]
    (report-line (format "ingest: %d inserted, %d duplicate, %d rejected%s"
                         (:inserted counts) (:duplicate counts) (:rejected counts)
                         (if (:dry-run options) " (dry run)" "")))
    (report-line (format "        %d targets, %d findings, %d packages"
                         (:targets totals) (:findings totals) (:packages totals)))
    ;; A rejection is a non-zero exit so CI notices (spec section 6.3).
    (if (pos? (:rejected counts)) 1 0)))

(defn cmd-check [_args]
  (let [checks (static/check)]
    (doseq [{:keys [tool ok? message]} checks]
      (report-line (if ok? "  ok  " " FAIL ") tool "-" message))
    (if (every? :ok? checks) 0 1)))

(defn cmd-render [args]
  (let [{:keys [options arguments]} (cli/parse-opts args render-options)
        profile (:profile options)
        opts    {:db (:db options) :scope (:scope options) :target-path (:out options)}]
    (if (:all options)
      (do (render/render-all! profile opts)
          (report-line "rendered" (count (render/notebooks)) "notebooks as" (name profile))
          0)
      (if-let [nb (first arguments)]
        (do (render/render! nb profile opts)
            (report-line "rendered" nb "as" (name profile))
            0)
        (do (report-line "usage: render <notebook> [--profile NAME] | render --all")
            1)))))

(defn cmd-report [args]
  (let [{:keys [options arguments]} (cli/parse-opts args report-options)
        results (render/report! {:notebooks (or (:notebooks options) (seq arguments))
                                 :profiles  (:profiles options)
                                 :db        (:db options)
                                 :scope     (:scope options)
                                 :target-path (:out options)})]
    (doseq [{:keys [notebook profile ok? error]} results]
      (report-line (if ok? "  ok  " " FAIL ") notebook (name profile)
                   (or error "")))
    (if (every? :ok? results) 0 1)))

(defn cmd-summary
  "Print the KPI map for the configured scope. The fastest way to see whether
  a store holds what you think it holds."
  [args]
  (let [{:keys [options]} (cli/parse-opts args common-options)
        conn (open-store options)
        c    (ctx/build {:connectable conn :scope (or (:scope options) :latest)})]
    (pp/pprint (:summary c))
    0))

;; ---------------------------------------------------------------------------

(defn cmd-enrich
  "Refresh EPSS, KEV and CIRCL data for vulnerabilities in the store."
  [args]
  (let [{:keys [options]} (cli/parse-opts args enrich-options)
        conn (open-store options)]
    (if (:status options)
      (do (pp/pprint (enrich/status conn)) 0)
      (let [{:keys [requested written offline? providers]}
            (enrich/enrich! conn {:max-age     (:max-age options)
                                  :concurrency (:concurrency options)
                                  :sightings?  (:sightings options)
                                  :offline?    (:offline options)
                                  :limit       (:limit options)})]
        (if offline?
          (report-line (format "enrich: offline, %d stale (nothing fetched)" requested))
          (report-line (format "enrich: %d requested, %d written, via %s"
                               requested written (str/join ", " providers))))
        0))))

(defn cmd-decisions
  "Import or export OpenVEX decisions (spec section 7.3).

    decisions import vex.json
    decisions export [file]
    decisions list"
  [args]
  (let [[sub & rest-args] args
        {:keys [options arguments]} (cli/parse-opts rest-args common-options)
        conn (open-store options)]
    (case sub
      "import"
      (if-let [file (first arguments)]
        (let [{:keys [statements decisions]} (vex/import! conn file)]
          (report-line (format "imported %d decisions from %d statements"
                               decisions statements))
          0)
        (do (report-line "usage: decisions import <vex.json>") 1))

      "export"
      (let [file (or (first arguments) "vex.json")
            {:keys [decisions]} (vex/export! conn file)]
        (report-line (format "exported %d decisions to %s" decisions file))
        0)

      "list"
      (do (pp/pprint (vex/summary conn)) 0)

      (do (report-line "usage: decisions <import|export|list> [file]") 1))))

(def tasks
  {"migrate"   #'cmd-migrate
   "ingest"    #'cmd-ingest
   "enrich"    #'cmd-enrich
   "decisions" #'cmd-decisions
   "check"     #'cmd-check
   "render"    #'cmd-render
   "report"    #'cmd-report
   "summary"   #'cmd-summary})

(defn usage []
  (str "vulcan <task> [options]\n\ntasks:\n"
       (str/join "\n" (map #(str "  " %) (sort (keys tasks))))
       "\n\nSee doc/ and `bb tasks` for details.\n"))

(defn -main [& args]
  (let [[task & rest-args] args]
    (if-let [f (get tasks task)]
      (let [code (f (vec rest-args))]
        (flush)
        (System/exit (or code 0)))
      (do (print (usage))
          (flush)
          (System/exit (if task 1 0))))))
