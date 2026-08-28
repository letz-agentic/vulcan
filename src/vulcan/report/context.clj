(ns vulcan.report.context
  "The report context: everything a notebook needs, computed once
  (spec section 8.1).

  This is the seam the whole design rests on. A notebook receives a context
  and derives from it; it never opens a connection, never writes SQL, and
  never recomputes a KPI. That is what lets one notebook render as a report
  and as a slide deck from identical numbers, and what lets a reader
  reproduce a report from its `scan_id` list alone."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [vulcan.analysis.categorize :as cat]
            [vulcan.analysis.core :as core]
            [vulcan.analysis.diff :as diff]
            [vulcan.analysis.score :as score]
            [vulcan.analysis.trend :as trend]
            [vulcan.store.db :as db]
            [vulcan.store.migrate :as migrate]
            [vulcan.store.query :as q])
  (:import (java.time Instant)))

(def default-profile
  "Profiles select representation, not content (spec section 9.2): the same
  context renders interactively for HTML and reveal.js, and as static images
  for pptx and PDF."
  :html)

(defn- setting
  "One configuration value from the ambient environment.

  Environment variables are the documented interface (spec section 11); the
  system property is the same setting reachable from inside a running JVM,
  which is how `vulcan.report.render` tells a notebook which profile it is
  being rendered under without spawning a process per notebook."
  [env-var property]
  (or (System/getenv env-var) (System/getProperty property)))

(defn config
  "Configuration, in precedence order (spec section 11):
  explicit argument > environment > `vulcan.edn` > defaults."
  ([] (config {}))
  ([overrides]
   (let [file      (io/file "vulcan.edn")
         from-file (when (.exists file)
                     (select-keys (edn/read-string (slurp file))
                                  [:db :scope :profile :top-n :weights :categorize]))
         db-set      (setting "VULCAN_DB" "vulcan.db")
         profile-set (setting "VULCAN_PROFILE" "vulcan.profile")
         scope-set   (setting "VULCAN_SCOPE" "vulcan.scope")]
     (merge {:db      db/default-db-path
             :scope   :latest
             :profile default-profile
             :top-n   20}
            from-file
            (cond-> {}
              db-set      (assoc :db db-set)
              profile-set (assoc :profile (keyword profile-set))
              scope-set   (assoc :scope (edn/read-string scope-set)))
            overrides))))

(defn build
  "Everything a notebook needs, computed once. Pure over the store.

  `:scope` is `:latest` (one scan per artifact -- the default and the meaning
  of \"current posture\"), `{:artifacts [..]}`, `{:scan-ids [..]}` or
  `{:since inst}`."
  [{:keys [db scope profile top-n categorize weights connectable]
    :or   {scope :latest profile default-profile top-n 20}}]
  (let [conn      (or connectable (migrate/open! (or db db/default-db-path)))
        scans     (q/scans conn scope)
        findings  (-> (q/findings conn scope)
                      (cat/categorize (merge cat/defaults categorize)))
        packages  (q/packages conn scope)
        scored    (score/score findings (merge score/default-weights weights))
        base      {:scans scans :findings findings :packages packages}]
    {:meta      {:generated-at (Instant/now)
                 :db-path      (if (string? db) db "(in-memory)")
                 :scope        scope
                 :profile      profile
                 :top-n        top-n
                 :scan-ids     (vec (distinct (:scan-id scans)))
                 :cache-age    (q/cache-age conn)
                 :thresholds   (merge cat/defaults categorize)
                 :weights      (merge score/default-weights weights)
                 :duckdb       (db/duckdb-version conn)}
     :conn      conn
     :scans     scans
     :findings  findings
     :packages  packages
     :summary   (core/summary base)
     :scored    scored
     :by-package (score/by-package scored)
     :diff      (diff/diff conn scope)
     :trend     (trend/trend conn)}))

(defn load!
  "Build a context from configuration, which is how a notebook obtains one
  (spec section 10.1 rule 1): `(def ctx (ctx/load!))` and nothing else."
  ([] (load! {}))
  ([overrides] (build (config overrides))))
