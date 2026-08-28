(ns vulcan.analysis.categorize
  "Four orthogonal axes, materialised as columns (spec section 8.2).

  Every chart in the toolkit facets on one of these, so they are columns and
  not predicates applied at plot time: a facet you cannot group by is not a
  facet. The thresholds are *data*, overridable per report context and printed
  in every report's appendix, because a number that moves silently is a number
  an auditor cannot trust."
  (:require [tablecloth.api :as tc]))

(def defaults
  "Thresholds for the exploitability axis, and the severity ordering used for
  sorting everywhere. Override via `(:categorize opts)` on the report context."
  {:epss-likely   0.1
   :epss-possible 0.01
   :severity-order ["CRITICAL" "HIGH" "MEDIUM" "LOW" "UNKNOWN"]})

(def severity-rank
  "CRITICAL is 0 so that ascending sorts put the worst first."
  (into {} (map-indexed (fn [i s] [s i])) (:severity-order defaults)))

;; ---------------------------------------------------------------------------
;; the axes

(defn exploitability
  "`exploited` (KEV or observed sightings) > `likely` (EPSS >= 0.1) >
  `possible` (EPSS >= 0.01) > `unlikely`.

  An unenriched finding is `unlikely`, not `unknown`: the axis answers \"what
  do we know that argues for urgency\", and absence of evidence argues for
  none. The report appendix carries the cache age so a reader can see how much
  of the store had been enriched when the report was made."
  [{:keys [epss-likely epss-possible]} {:keys [exploited kev epss-score]}]
  (let [epss (or epss-score 0.0)]
    (cond
      (or exploited kev)      "exploited"
      (>= epss epss-likely)   "likely"
      (>= epss epss-possible) "possible"
      :else                   "unlikely")))

(defn fixability
  "Derived from Trivy's own status vocabulary (spec section 5.3), so that the
  store and the scanner never disagree about what is fixable.

  `vendor-declined` is kept visible rather than filtered out, which is the
  whole reason ingestion never applies `--ignore-unfixed`: the unfixable
  backlog is exactly what management needs to see."
  [{:keys [status fixed-version]}]
  (case (or status "unknown")
    "fixed"               (if (seq fixed-version) "fixable" "pending")
    ("will_not_fix"
     "end_of_life"
     "not_affected")      "vendor-declined"
    ("affected"
     "fix_deferred"
     "under_investigation") "pending"
    "unknown"))

(defn exposure
  "Where the finding lives, from the Trivy result class."
  [{:keys [target-class]}]
  (case (or target-class "")
    "os-pkgs"   "os"
    "lang-pkgs" "lang"
    "config"    "config"
    "secret"    "secret"
    "license"   "license"
    "unknown"))

;; ---------------------------------------------------------------------------

(defn categorize
  "Add `:exploitability`, `:fixability`, `:exposure` and `:severity-rank` to a
  findings dataset. Idempotent, so a notebook can call it without checking."
  ([ds] (categorize ds defaults))
  ([ds opts]
   (if (zero? (tc/row-count ds))
     ds
     (let [opts (merge defaults opts)]
       (tc/map-rows ds (fn [row]
                         {:exploitability (exploitability opts row)
                          :fixability     (fixability row)
                          :exposure       (exposure row)
                          :severity-rank  (get severity-rank (:severity row)
                                               (count severity-rank))}))))))
