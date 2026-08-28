(ns vulcan.analysis.trend
  "Posture over time (spec section 8.4).

  `v_scan_summary` already carries per-scan counts; this namespace turns them
  into something plottable: a long-format dataset (one row per scan per
  severity) because that is what every grammar-of-graphics layer wants, plus
  an optional weekly resample for when scans are irregular."
  (:require [tablecloth.api :as tc]
            [vulcan.store.query :as q])
  (:import (java.time Instant ZoneOffset)
           (java.time.temporal ChronoUnit)))

(def severity-count-columns
  {:n-critical "CRITICAL"
   :n-high     "HIGH"
   :n-medium   "MEDIUM"
   :n-low      "LOW"
   :n-unknown  "UNKNOWN"})

(defn- ->instant [t]
  (cond
    (instance? Instant t)        t
    (instance? java.util.Date t) (.toInstant ^java.util.Date t)
    :else                        nil))

(defn week-start
  "Midnight UTC on the Monday of `t`'s week. Used to bucket irregular scan
  cadences into a line that does not jitter."
  [t]
  (when-let [i (->instant t)]
    (let [d (.toLocalDate (.atZone i ZoneOffset/UTC))
          m (.minusDays d (long (dec (.getValue (.getDayOfWeek d)))))]
      (.toInstant (.atStartOfDay m ZoneOffset/UTC)))))

(defn long-format
  "One row per (scan, severity): `artifact-name`, `created-at`, `severity`,
  `n`. This is the shape `trend-lines` plots."
  [summary-ds]
  (if (zero? (tc/row-count summary-ds))
    (tc/dataset {:artifact-name [] :created-at [] :severity [] :n []}
                {:dataset-name "trend"})
    (-> (for [row (tc/rows summary-ds :as-maps)
              [col severity] severity-count-columns]
          {:scan-id       (:scan-id row)
           :artifact-name (:artifact-name row)
           :created-at    (:created-at row)
           :severity      severity
           :n             (or (get row col) 0)})
        (tc/dataset {:dataset-name "trend"}))))

(defn resample-weekly
  "Collapse to one point per artifact per severity per ISO week, taking the
  *last* scan in each week rather than the sum: two scans of the same image in
  one week are two observations of one posture, not twice the vulnerabilities."
  [trend-ds]
  (if (zero? (tc/row-count trend-ds))
    trend-ds
    (-> trend-ds
        (tc/map-columns :week [:created-at] week-start)
        (tc/group-by [:artifact-name :severity :week])
        (tc/aggregate {:n (fn [g]
                            (->> (tc/rows g :as-maps)
                                 (sort-by :created-at)
                                 last
                                 :n))})
        (tc/order-by [:week :artifact-name :severity]))))

(defn trend
  "Trend over *every* scan in the store, not just those in scope: a trend line
  restricted to the current scope is not a trend (spec section 8.4)."
  ([connectable] (trend connectable {}))
  ([connectable {:keys [weekly?]}]
   (let [t (long-format (q/scan-summary connectable))]
     (if weekly? (resample-weekly t) t))))

(defn days-between [a b]
  (when (and (->instant a) (->instant b))
    (.between ChronoUnit/DAYS (->instant a) (->instant b))))
