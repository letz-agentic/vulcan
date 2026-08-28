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

(def tasks
  {"migrate" #'cmd-migrate
   "ingest"  #'cmd-ingest
   "check"   #'cmd-check
   "render"  #'cmd-render
   "report"  #'cmd-report
   "summary" #'cmd-summary})

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
