(ns vulcan.ingest.dir
  "The ingestion driver: files and directories in, `ingest_log` rows out
  (spec sections 6.1-6.3).

  Failure policy is per-file, not per-run: a malformed report is rejected as a
  whole, recorded, and the run continues with the next file. The caller gets a
  summary whose `:rejected` count is what the CLI turns into an exit code."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.tools.logging :as log]
            [vulcan.ingest.json :as vj]
            [vulcan.ingest.schema :as schema]
            [vulcan.ingest.trivy :as trivy]
            [vulcan.store.write :as write])
  (:import (java.time Instant)))

(defn json-files
  "Report files under `path`. A file is taken as-is; a directory is walked
  recursively for `*.json` (spec section 6.1). Results are sorted so a run is
  reproducible and its log is diffable."
  [path]
  (let [f (io/file path)]
    (cond
      (not (.exists f)) (throw (ex-info "No such path" {:path (str path)}))
      (.isFile f)       [f]
      :else             (->> (file-seq f)
                             (filter #(.isFile ^java.io.File %))
                             (filter #(str/ends-with? (str/lower-case (.getName ^java.io.File %))
                                                      ".json"))
                             (sort-by #(.getPath ^java.io.File %))
                             vec))))

(defn ingest-file!
  "Ingest one report. Returns `{:outcome :inserted|:duplicate|:rejected ...}`.

  `:dry-run?` stops after parse and validation, which is how you check a
  directory of reports without touching the store."
  [connectable file {:keys [dry-run?] :as _opts}]
  (let [source-file (.getPath (io/file file))]
    (try
      (let [bytes   (vj/read-bytes file)
            scan-id (vj/sha256 bytes)]
        (cond
          (and (not dry-run?) (write/scan-exists? connectable scan-id))
          (do (write/log-ingest! connectable {:scan-id scan-id :source-file source-file
                                              :outcome :duplicate :message nil})
              {:outcome :duplicate :scan-id scan-id :source-file source-file})

          :else
          (let [report (vj/parse bytes)]
            (if-let [problem (schema/validate report)]
              (do
                (when-not dry-run?
                  (write/log-ingest! connectable {:scan-id scan-id :source-file source-file
                                                  :outcome :rejected
                                                  :message (:message problem)}))
                (log/warnf "rejected %s: %s" source-file (:message problem))
                {:outcome :rejected :scan-id scan-id :source-file source-file
                 :reason (:reason problem) :message (:message problem)})
              (let [rows (trivy/report->rows report {:scan-id     scan-id
                                                     :source-file source-file
                                                     :ingested-at (Instant/now)})]
                (if dry-run?
                  {:outcome :inserted :scan-id scan-id :source-file source-file
                   :dry-run true
                   :inserted {:targets  (count (:targets rows))
                              :findings (count (:findings rows))
                              :packages (count (:packages rows))}}
                  (let [res (write/write-rows! connectable rows)]
                    (write/log-ingest! connectable {:scan-id scan-id :source-file source-file
                                                    :outcome :inserted :message nil})
                    (assoc res :outcome :inserted :source-file source-file))))))))
      (catch Exception e
        ;; A malformed report is an expected outcome, not a crash: log the
        ;; reason, not a stack trace, so a directory with one bad file does
        ;; not bury the run summary. The exception itself goes to debug for
        ;; when the message alone is not enough.
        (log/warnf "rejected %s: %s" source-file (.getMessage e))
        (log/debug e "rejection detail")
        (let [msg (str (.getSimpleName (.getClass e)) ": " (.getMessage e))]
          (when-not dry-run?
            (try
              (write/log-ingest! connectable {:scan-id nil :source-file source-file
                                              :outcome :rejected :message msg})
              (catch Exception _ nil)))
          {:outcome :rejected :source-file source-file :reason :exception :message msg})))))

(defn ingest!
  "Ingest every report under each of `paths`. Returns
  `{:results [..] :counts {:inserted n :duplicate n :rejected n} :totals {..}}`."
  [connectable paths opts]
  (let [files   (mapcat json-files paths)
        results (mapv #(ingest-file! connectable % opts) files)
        counts  (merge {:inserted 0 :duplicate 0 :rejected 0}
                       (frequencies (map :outcome results)))]
    {:results results
     :counts  counts
     :totals  (reduce (fn [acc r]
                        (merge-with + acc (or (:inserted r) {})))
                      {:targets 0 :findings 0 :packages 0}
                      results)}))
