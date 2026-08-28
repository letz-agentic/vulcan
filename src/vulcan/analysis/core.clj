(ns vulcan.analysis.core
  "KPIs and the small aggregations every audience shares (spec section 8).

  The rule this namespace exists to enforce: numbers quoted in prose are
  computed once, here, and interpolated (spec section 10.1 rule 6). A notebook
  that types a number into a sentence can disagree with its own chart; a
  notebook that interpolates `(:n-critical (:summary ctx))` cannot."
  (:require [tablecloth.api :as tc]
            [vulcan.analysis.categorize :as cat]))

(defn- n-where [ds pred]
  (->> (tc/rows ds :as-maps) (filter pred) count))

(defn- median [xs]
  (let [v (vec (sort (remove nil? xs)))
        n (count v)]
    (when (pos? n)
      (if (odd? n)
        (double (nth v (quot n 2)))
        (/ (+ (double (nth v (dec (quot n 2)))) (double (nth v (quot n 2)))) 2.0)))))

(defn severity-counts
  "Counts by severity, in severity order, including zeroes.

  Zeroes matter: a bar chart that silently drops CRITICAL because there are
  none reads as \"we did not measure it\", not as \"there are none\"."
  [findings-ds]
  (let [counts (frequencies (:severity findings-ds))]
    (tc/dataset {:severity (:severity-order cat/defaults)
                 :n        (mapv #(get counts % 0) (:severity-order cat/defaults))}
                {:dataset-name "severity-counts"})))

(defn axis-counts
  "Counts along one categorisation axis, as a dataset."
  [findings-ds axis]
  (if (zero? (tc/row-count findings-ds))
    (tc/dataset {axis [] :n []} {:dataset-name (name axis)})
    (-> findings-ds
        (tc/group-by [axis])
        (tc/aggregate {:n tc/row-count})
        (tc/order-by [:n] [:desc])
        (tc/set-dataset-name (name axis)))))

(defn summary
  "The KPI map. Small, stable and printed in the appendix; these are the
  numbers management sees quarter after quarter, so adding to this map is
  cheap and removing from it is not."
  [{:keys [findings scans packages]}]
  (let [rows (tc/rows findings :as-maps)
        sev  (frequencies (map :severity rows))]
    {:n-artifacts   (-> scans :artifact-name distinct count)
     :n-scans       (tc/row-count scans)
     :n-findings    (tc/row-count findings)
     :n-vulns       (-> findings :vulnerability-id distinct count)
     :n-critical    (get sev "CRITICAL" 0)
     :n-high        (get sev "HIGH" 0)
     :n-medium      (get sev "MEDIUM" 0)
     :n-low         (get sev "LOW" 0)
     :n-unknown     (get sev "UNKNOWN" 0)
     :n-fixable     (n-where findings #(= "fixable" (:fixability %)))
     :n-declined    (n-where findings #(= "vendor-declined" (:fixability %)))
     :n-exploited   (n-where findings #(= "exploited" (:exploitability %)))
     :n-packages    (tc/row-count packages)
     :n-affected-packages (-> findings :pkg-name distinct count)
     ;; A fraction only means something when we have the denominator, which is
     ;; to say only when the scans were run with --list-all-pkgs.
     :pct-packages-affected
     (when (pos? (tc/row-count packages))
       (* 100.0 (/ (double (-> findings :pkg-name distinct count))
                   (double (-> packages :pkg-name distinct count)))))
     :median-age-days (median (map :age-days rows))
     :median-cvss     (median (map :cvss-v3-score rows))}))

(defn top-findings
  "The first `n` scored findings, with only the columns a reader needs. Wide
  datasets are for the REPL; a report table is a chosen subset."
  ([scored-ds] (top-findings scored-ds 20))
  ([scored-ds n]
   (if (zero? (tc/row-count scored-ds))
     scored-ds
     (-> scored-ds
         (tc/select-columns [:vulnerability-id :severity :pkg-name
                             :installed-version :fixed-version :fixability
                             :exploitability :artifact-name :n-artifacts
                             :age-days :fix-first-score])
         (tc/head n)))))
