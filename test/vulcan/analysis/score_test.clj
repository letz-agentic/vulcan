(ns vulcan.analysis.score-test
  "Property tests for the fix-first score (spec section 8.3).

  The score decides what an engineer works on first. Two properties are what
  make that ranking defensible, and both are easy to break with an innocent
  edit to a weight table -- so they are asserted, not assumed."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [vulcan.analysis.score :as score]))

(def severities ["UNKNOWN" "LOW" "MEDIUM" "HIGH" "CRITICAL"])
(def fixabilities ["vendor-declined" "unknown" "pending" "fixable"])

(def gen-finding
  (gen/hash-map
   :severity        (gen/elements severities)
   :fixability      (gen/elements fixabilities)
   :kev             gen/boolean
   :exploited       gen/boolean
   :epss-percentile (gen/one-of [(gen/return nil) (gen/double* {:min 0.0 :max 1.0
                                                               :NaN? false :infinite? false})])
   :age-days        (gen/one-of [(gen/return nil) (gen/choose 0 2000)])
   :n-artifacts     (gen/choose 1 64)))

;; ---------------------------------------------------------------------------
;; range

(defspec score-stays-in-unit-interval 300
  (prop/for-all [f gen-finding]
    (let [s (score/score-row f)]
      (and (<= 0.0 s) (<= s 1.0)))))

(deftest weights-sum-to-one
  (testing "so the score reads as a fraction, not an arbitrary magnitude"
    ;; Exact equality is the wrong assertion for a sum of doubles:
    ;; 0.35+0.30+0.20+0.10+0.05 is 0.9999999999999999 in binary floating point.
    (is (> 1e-9 (abs (- 1.0 (reduce + (vals score/default-weights))))))))

;; ---------------------------------------------------------------------------
;; monotonicity: raising any one input never lowers the score

(defspec severity-is-monotonic 200
  (prop/for-all [f gen-finding
                 i (gen/choose 0 (dec (count severities)))
                 j (gen/choose 0 (dec (count severities)))]
    (let [[lo hi] (sort [i j])]
      (<= (score/score-row (assoc f :severity (nth severities lo)))
          (score/score-row (assoc f :severity (nth severities hi)))))))

(defspec fixability-is-monotonic 200
  (prop/for-all [f gen-finding
                 i (gen/choose 0 (dec (count fixabilities)))
                 j (gen/choose 0 (dec (count fixabilities)))]
    (let [[lo hi] (sort [i j])]
      (<= (score/score-row (assoc f :fixability (nth fixabilities lo)))
          (score/score-row (assoc f :fixability (nth fixabilities hi)))))))

(defspec spread-is-monotonic 200
  (prop/for-all [f gen-finding
                 a (gen/choose 1 200)
                 b (gen/choose 1 200)]
    (let [[lo hi] (sort [a b])]
      (<= (score/score-row (assoc f :n-artifacts lo))
          (score/score-row (assoc f :n-artifacts hi))))))

(defspec age-is-monotonic 200
  (prop/for-all [f gen-finding
                 a (gen/choose 0 2000)
                 b (gen/choose 0 2000)]
    (let [[lo hi] (sort [a b])]
      (<= (score/score-row (assoc f :age-days lo))
          (score/score-row (assoc f :age-days hi))))))

(defspec exploitability-is-monotonic 200
  (prop/for-all [f gen-finding
                 a (gen/double* {:min 0.0 :max 1.0 :NaN? false :infinite? false})
                 b (gen/double* {:min 0.0 :max 1.0 :NaN? false :infinite? false})]
    (let [[lo hi] (sort [a b])
          base    (assoc f :kev false :exploited false)]
      (<= (score/score-row (assoc base :epss-percentile lo))
          (score/score-row (assoc base :epss-percentile hi))))))

(defspec kev-dominates-epss 200
  (prop/for-all [f gen-finding
                 p (gen/double* {:min 0.0 :max 1.0 :NaN? false :infinite? false})]
    (>= (score/score-row (assoc f :kev true))
        (score/score-row (assoc f :kev false :exploited false :epss-percentile p)))))

;; ---------------------------------------------------------------------------
;; the headline property

(defspec kev-critical-fixable-outranks-anything-without-kev 300
  (prop/for-all [other gen-finding]
    (let [worst {:severity "CRITICAL" :fixability "fixable" :kev true
                 :exploited true :age-days 365 :n-artifacts 64}
          other (assoc other :kev false :exploited false)]
      (>= (score/score-row worst) (score/score-row other)))))

;; ---------------------------------------------------------------------------
;; components

(deftest component-ranges
  (testing "every component is normalised to [0,1]"
    (is (= 1.0 (score/sev-component "CRITICAL")))
    (is (= 0.0 (score/sev-component "UNKNOWN")))
    (is (= 0.0 (score/sev-component "NOT-A-SEVERITY")))
    (is (= 1.0 (score/fix-component "fixable")))
    (is (= 0.0 (score/fix-component "vendor-declined")))
    (is (= 0.0 (score/spread-component 1)) "one artifact is no spread at all")
    (is (= 1.0 (score/spread-component 32)))
    (is (= 1.0 (score/spread-component 10000)) "saturates rather than running away")
    (is (= 0.0 (score/age-component nil)) "an unknown date is not guessed at")
    (is (= 0.0 (score/age-component 0)))
    (is (= 1.0 (score/age-component 365)))
    (is (= 1.0 (score/age-component 100000)))))

(deftest exploit-component-prefers-percentile-over-raw-score
  (testing "percentile is what makes two CVEs comparable"
    (is (= 0.9 (score/exploit-component {:epss-percentile 0.9 :epss-score 0.1})))
    (is (= 0.1 (score/exploit-component {:epss-score 0.1})))
    (is (= 0.0 (score/exploit-component {})))
    (is (= 1.0 (score/exploit-component {:kev true :epss-percentile 0.0})))))

(deftest unenriched-finding-still-scores
  (testing "no EPSS and no KEV must not produce nil or NaN"
    (let [s (score/score-row {:severity "HIGH" :fixability "fixable"})]
      (is (number? s))
      (is (not (Double/isNaN s)))
      (is (pos? s)))))
