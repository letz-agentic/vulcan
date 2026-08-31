(ns vulcan.analysis.score
  "The fix-first score (spec section 8.3).

  A weighted sum of five components, each normalised to [0,1], with weights
  that sum to 1 -- so the score itself is in [0,1] and can be read as a
  fraction rather than as an arbitrary magnitude.

    score = w_sev    * sev(severity)
          + w_exp    * exp(epss, kev)
          + w_fix    * fix(fixability)
          + w_spread * spread(n_artifacts)
          + w_age    * age(published_date)

  Two properties are asserted by test rather than by inspection, because they
  are what make the ranking defensible:

    * monotonicity -- raising any single input never lowers the score;
    * a KEV, CRITICAL, fixable finding outranks anything without KEV.

  The weights are a single set for every audience, not per-audience (spec
  section 13, open question 4). Per-audience weights invite the \"why did the
  number change\" conversation, and the appendix prints these values so the
  reader can see exactly what produced the ranking."
  (:require [clojure.string :as str]
            [tablecloth.api :as tc]
            [vulcan.analysis.categorize :as cat]))

(def default-weights
  {:severity 0.35
   :exploit  0.30
   :fix      0.20
   :spread   0.10
   :age      0.05})

(def severity-weight
  {"CRITICAL" 1.0 "HIGH" 0.7 "MEDIUM" 0.4 "LOW" 0.1 "UNKNOWN" 0.0})

(def fixability-weight
  "Fixable work floats up because it is work that can actually be done today.
  `vendor-declined` scores zero on this axis but is not excluded: it still
  carries severity and exploitability."
  {"fixable" 1.0 "pending" 0.3 "vendor-declined" 0.0 "unknown" 0.1})

(def age-saturation-days
  "Beyond a year, older is not more urgent -- it is just older."
  365.0)

(def spread-saturation-artifacts
  "Spread component saturates at this many artifacts, so that one widely-used
  package does not drown out everything else. 32 is log2(32)=5, giving a nice
  integer log scale where 2 artifacts = 0.2, 4 = 0.4, 8 = 0.6, 16 = 0.8, 32+ = 1.0."
  32)

;; ---------------------------------------------------------------------------
;; components, each [0,1]

(defn sev-component [severity]
  (get severity-weight severity 0.0))

(defn exploit-component
  "KEV is certainty of exploitation and saturates the axis. Otherwise the EPSS
  percentile is used in preference to the raw probability, because percentile
  is what makes two CVEs comparable; the raw score is the fallback."
  [{:keys [kev exploited epss-percentile epss-score]}]
  (cond
    (or kev exploited)      1.0
    (some? epss-percentile) (double (max 0.0 (min 1.0 epss-percentile)))
    (some? epss-score)      (double (max 0.0 (min 1.0 epss-score)))
    :else                   0.0))

(defn fix-component [fixability]
  (get fixability-weight fixability 0.0))

(defn spread-component
  "Log-scaled count of artifacts affected in scope, so that one upgrade fixing
  many images floats up without a single widely-used package drowning out
  everything else. Saturates at `spread-saturation-artifacts`."
  [n-artifacts]
  (let [n (max 1 (or n-artifacts 1))]
    (min 1.0 (/ (Math/log (double n)) (Math/log (double spread-saturation-artifacts))))))

(defn age-component
  "Saturating at `age-saturation-days`. A finding with no publication date
  scores zero here rather than being guessed at."
  [age-days]
  (if (nil? age-days)
    0.0
    (min 1.0 (/ (double (max 0 age-days)) age-saturation-days))))

;; ---------------------------------------------------------------------------

(defn score-row
  "Composite score for one categorised finding row. `:n-artifacts` is supplied
  by `score` from the scope, not read from the row."
  ([row] (score-row row default-weights))
  ([{:keys [severity fixability age-days n-artifacts] :as row} weights]
   (let [w (merge default-weights weights)]
     (+ (* (:severity w) (sev-component severity))
        (* (:exploit  w) (exploit-component row))
        (* (:fix      w) (fix-component fixability))
        (* (:spread   w) (spread-component n-artifacts))
        (* (:age      w) (age-component age-days))))))

(defn- artifact-spread
  "How many distinct artifacts in scope each vulnerability touches."
  [ds]
  (-> ds
      (tc/group-by [:vulnerability-id])
      (tc/aggregate {:n-artifacts (fn [g] (-> g :artifact-name distinct count))})
      (tc/rename-columns {:$group-name :vulnerability-id})))

(defn score
  "Add `:n-artifacts` and `:fix-first-score` to a categorised findings dataset,
  ordered worst-first.

  Rank is by score and then by `n-artifacts`, so that when two findings tie,
  the one whose fix clears more images wins -- that tiebreak is the whole
  point of the \"fix by package\" view (spec section 8.3)."
  ([ds] (score ds default-weights))
  ([ds weights]
   (if (zero? (tc/row-count ds))
     (tc/add-columns ds {:n-artifacts [] :fix-first-score []})
     (let [spread (artifact-spread ds)]
       (-> ds
           (tc/left-join spread [:vulnerability-id])
           (tc/map-rows (fn [row] {:fix-first-score (score-row row weights)}))
           (tc/order-by [:fix-first-score :n-artifacts] [:desc :desc])
           (tc/set-dataset-name "scored"))))))

(defn by-package
  "The engineering deliverable: one row per upgrade, worst first.

  Grouping by package *and* target fixed version answers \"what single change
  clears the most, most-urgent findings\", which is a different question from
  \"which CVE is worst\" and the one an engineer actually acts on."
  [scored-ds]
  (if (zero? (tc/row-count scored-ds))
    scored-ds
    (-> scored-ds
        (tc/group-by [:pkg-name :fixed-version])
        ;; Aggregators return scalars, never one-element vectors: tablecloth
        ;; reads a sequence as several columns and would name them
        ;; `:artifacts-0`, `:vulnerabilities-0` and so on.
        (tc/aggregate {:n-findings  tc/row-count
                       :n-artifacts (fn [g] (-> g :artifact-name distinct count))
                       :artifacts   (fn [g] (->> g :artifact-name distinct sort
                                                 (str/join ", ")))
                       :max-score   (fn [g] (reduce max (:fix-first-score g)))
                       :total-score (fn [g] (reduce + (:fix-first-score g)))
                       :worst-severity (fn [g] (->> g :severity
                                                    (sort-by #(get cat/severity-rank % 99))
                                                    first))
                       :vulnerabilities (fn [g] (->> g :vulnerability-id distinct sort
                                                     (str/join " ")))})
        (tc/order-by [:total-score] [:desc])
        (tc/set-dataset-name "by-package"))))
