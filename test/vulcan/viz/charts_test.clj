(ns vulcan.viz.charts-test
  "Spec section 12: every chart function renders to both targets on the fixture
  context without exception, and the static SVG is non-empty and within a size
  budget.

  This is the test that protects the property the whole notebook design rests
  on: a chart that cannot produce a static form is a chart that will silently
  vanish from a PowerPoint deck."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [tablecloth.api :as tc]
            [vulcan.report.kinds :as k]
            [vulcan.test-store :as ts]
            [vulcan.viz.charts :as charts]
            [vulcan.viz.static :as static]
            [vulcan.viz.theme :as theme]))

(def svg-size-budget
  "A chart bigger than this is almost certainly a mistake -- an unaggregated
  dataset plotted point by point, for example."
  (* 512 1024))

(defn- vl-available?
  "The static tests need the pinned binary. Where it is absent (a machine that
  has not run the install step) we say so loudly rather than passing quietly."
  []
  (->> (static/check) (filter #(= "vl-convert" (:tool %))) first :ok?))

;; ---------------------------------------------------------------------------

(deftest every-chart-builds-for-both-targets
  (ts/with-store [conn]
    (let [ctx (ts/context conn)]
      (doseq [[label f] charts/all-charts]
        (testing (str (name label) " builds a Plotly spec")
          (let [spec (f ctx {:target :plotly})]
            (is (map? spec))
            (is (contains? spec :data) (str label " has traces"))
            (is (contains? spec :layout))))

        (testing (str (name label) " builds a Vega-Lite spec")
          (let [spec (f ctx {:target :vega-lite})]
            (is (map? spec))
            (is (or (contains? spec :mark)
                    (contains? spec :layer))
                (str label " has a mark or layers"))
            (is (contains? spec :data))))))))

(deftest every-chart-renders-to-svg
  (if-not (vl-available?)
    (is false "vl-convert is not installed; see README 'Pinned tools'")
    (ts/with-store [conn]
      (let [ctx (ts/context conn)
            r   (static/renderer)]
        (doseq [[label f] charts/all-charts]
          (testing (str (name label) " renders to a static SVG")
            (let [svg (static/render-svg r (f ctx {:target :vega-lite}))]
              (is (str/starts-with? (str/trim svg) "<svg")
                  (str label " produced something that is not an SVG"))
              (is (< 200 (count svg)) (str label " produced an empty SVG"))
              (is (< (count svg) svg-size-budget)
                  (str label " exceeded the SVG size budget")))))))))

(deftest charts-survive-an-empty-context
  (testing "a report over a store with no findings must render, not throw"
    (ts/with-store [conn ts/fresh-store]
      (let [ctx (ts/context conn)]
        (doseq [[label f] charts/all-charts
                target [:plotly :vega-lite]]
          (is (map? (f ctx {:target target}))
              (str label " threw on an empty context for " target)))))))

(deftest charts-accept-a-dataset-or-a-context
  (ts/with-store [conn]
    (let [ctx (ts/context conn)]
      (is (map? (charts/severity-bars ctx {:target :plotly})))
      (is (map? (charts/severity-bars (:findings ctx) {:target :plotly}))))))

(deftest fix-first-table-is-a-dataset-not-a-chart
  (ts/with-store [conn]
    (let [t (charts/fix-first-table (ts/context conn) {:top-n 5})]
      (is (tc/dataset? t))
      (is (= 5 (tc/row-count t))))))

;; ---------------------------------------------------------------------------
;; theme

(deftest severity-palette-covers-every-severity
  (testing "an unstyled severity would plot in an arbitrary colour"
    (is (every? theme/severity-colors
                ["CRITICAL" "HIGH" "MEDIUM" "LOW" "UNKNOWN"]))))

(deftest severity-palette-is-monotonic-in-lightness
  (testing "so the ramp survives greyscale and colour blindness"
    (let [luminance (fn [hex]
                      (let [[r g b] (map #(Integer/parseInt
                                           (subs hex % (+ % 2)) 16)
                                         [1 3 5])]
                        (+ (* 0.2126 r) (* 0.7152 g) (* 0.0722 b))))
          ordered   ["CRITICAL" "HIGH" "MEDIUM" "LOW" "UNKNOWN"]
          lums      (mapv #(luminance (theme/severity-colors %)) ordered)]
      (is (= lums (vec (sort lums)))
          (str "severity colours must get lighter as severity falls: "
               (zipmap ordered lums))))

    (testing "and the exploitability ramp too"
      (let [luminance (fn [hex]
                        (let [[r g b] (map #(Integer/parseInt (subs hex % (+ % 2)) 16)
                                           [1 3 5])]
                          (+ (* 0.2126 r) (* 0.7152 g) (* 0.0722 b))))
            ordered   ["exploited" "likely" "possible" "unlikely"]
            lums      (mapv #(luminance (theme/exploitability-colors %)) ordered)]
        (is (= lums (vec (sort lums))) (str (zipmap ordered lums)))))))

(deftest palette-domain-is-stable-and-restricted
  (testing "legend order does not change just because a severity is absent"
    (is (= ["CRITICAL" "HIGH"]
           (theme/ordered-domain theme/severity-colors ["HIGH" "CRITICAL"])))
    (is (= ["CRITICAL" "HIGH"]
           (theme/ordered-domain theme/severity-colors ["CRITICAL" "HIGH" "HIGH"])))
    (is (= [(theme/severity-colors "CRITICAL") (theme/severity-colors "HIGH")]
           (theme/range-for theme/severity-colors ["HIGH" "CRITICAL"])))))

(deftest unknown-category-still-gets-a-colour
  (is (string? (theme/color-for theme/change-colors "something-new" 0))))

;; ---------------------------------------------------------------------------
;; profile-driven representation (spec 9.2)

(deftest profile-decides-representation
  (ts/with-store [conn]
    (let [interactive (ts/context conn)
          static-ctx  (assoc-in (ts/context conn) [:meta :profile] :pptx)]
      (is (k/interactive? interactive))
      (is (not (k/interactive? static-ctx)))
      (testing "html and revealjs are interactive; pptx and pdf are not"
        (doseq [p [:html :revealjs]]
          (is (k/interactive? (assoc-in interactive [:meta :profile] p))))
        (doseq [p [:pptx :pdf]]
          (is (not (k/interactive? (assoc-in interactive [:meta :profile] p)))))))))

(deftest tables-truncate-visibly
  (testing "a shortened list that does not say so reads as complete"
    (ts/with-store [conn]
      (let [ctx    (assoc-in (ts/context conn) [:meta :profile] :pptx)
            scored (:scored ctx)
            out    (k/table ctx scored {:top-n 3})
            text   (-> out first str)]
        (is (str/includes? text "Showing the top 3 of"))))))

(deftest static-table-is-markdown-not-html
  (testing "Pandoc turns a Markdown table into a real PowerPoint table"
    (ts/with-store [conn]
      (let [ctx  (assoc-in (ts/context conn) [:meta :profile] :pptx)
            out  (k/table ctx (charts/fix-first-table ctx {:top-n 2}) {:top-n 2})
            text (-> out first str)]
        (is (str/includes? text "| vulnerability id |"))
        (is (str/includes? text "---"))))))

(deftest when-profile-gates-content
  (ts/with-store [conn]
    (let [ctx (ts/context conn)]
      (is (= :shown (k/when-profile ctx #{:html} :shown)))
      (testing "a non-matching profile yields an empty fragment, not nil"
        ;; Clay renders a form's value, so returning nil puts the literal
        ;; text "nil" in the middle of the report.
        (let [hidden (k/when-profile ctx #{:pptx} :hidden)]
          (is (not= :hidden hidden))
          (is (empty? (vec hidden))))))))

(deftest appendix-carries-provenance
  (ts/with-store [conn]
    (let [text (-> (k/appendix (ts/context conn)) first str)]
      (is (str/includes? text "Data provenance"))
      (is (str/includes? text "Fix-first weights"))
      (is (str/includes? text "DuckDB"))
      (testing "and names every scan, so the report is reproducible"
        (doseq [id (get-in (ts/context conn) [:meta :scan-ids])]
          (is (str/includes? text id)))))))
