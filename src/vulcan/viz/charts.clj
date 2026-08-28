(ns vulcan.viz.charts
  "The chart toolkit (spec section 9.1).

  A small, opinionated set. Each function takes a dataset (or the report
  context) plus `{:target :plotly | :vega-lite}` and returns a plot spec for
  that target. Nothing here decides *which* target to use -- that is
  `vulcan.report.kinds/chart`, driven by the output profile -- because the
  same chart must be renderable interactively for HTML and reveal.js and as a
  static image for pptx and PDF (spec section 9.2).

  The two targets are not interchangeable implementations of one API: Plotly
  wants traces and a layout, Vega-Lite wants an encoding grammar. Rather than
  pretend otherwise behind a lowest-common-denominator wrapper, each chart
  states both forms explicitly. It is more code, and it is the code that
  actually renders."
  (:require [clojure.string :as str]
            [scicloj.tableplot.v1.plotly :as plotly]
            [tablecloth.api :as tc]
            [vulcan.analysis.core :as core]
            [vulcan.analysis.diff :as diff]
            [vulcan.viz.theme :as theme]))

(def default-target :plotly)

(defn- target-of [opts] (or (:target opts) default-target))

(defn- ctx->findings
  "Charts accept either a dataset or the whole context, so a notebook can
  write `(charts/severity-bars ctx)` without unpacking."
  [x]
  (if (and (map? x) (contains? x :findings)) (:findings x) x))

;; ---------------------------------------------------------------------------
;; Vega-Lite building blocks
;;
;; Data is inlined as `:values`. vl-convert has no access to our DuckDB file
;; and must render offline, so a URL-backed spec would be unrenderable.

(defn- vl
  [{:keys [title width height]} layer]
  (merge {:$schema "https://vega.github.io/schema/vega-lite/v5.json"
          :config  (theme/vega-config)
          :width   (or width 520)
          :height  (or height 320)}
         (when title {:title title})
         layer))

(defn- vl-values [ds cols]
  {:values (mapv #(select-keys % cols) (tc/rows ds :as-maps))})

(defn- vl-color
  "A colour encoding pinned to a fixed palette, with an explicit domain so the
  legend order does not change between two renders of the same chart."
  [field palette present]
  {:field field
   :type  "nominal"
   :title (theme/severity-title (keyword field))
   :scale {:domain (theme/ordered-domain palette present)
           :range  (theme/range-for palette present)}
   :sort  (theme/ordered-domain palette present)})

;; ---------------------------------------------------------------------------
;; Plotly building blocks

(defn- plotly-fig [traces layout-title]
  ^{:kindly/kind :kind/plotly}
  {:data (vec traces)
   :layout (theme/plotly-layout layout-title)})

(defn- bar-trace [xs ys name color]
  (cond-> {:type "bar" :x (vec xs) :y (vec ys)}
    name  (assoc :name name)
    color (assoc :marker {:color color})))

;; ---------------------------------------------------------------------------
;; 1. severity-bars

(defn severity-bars
  "Findings by severity. Zero counts are kept: a missing bar reads as \"not
  measured\", which is not what an empty severity means."
  ([x] (severity-bars x {}))
  ([x opts]
   (let [ds     (ctx->findings x)
         counts (core/severity-counts ds)
         sevs   (vec (:severity counts))
         ns     (vec (:n counts))
         title  (:title opts "Findings by severity")]
     (case (target-of opts)
       :vega-lite
       (vl (assoc opts :title title)
           {:data (vl-values counts [:severity :n])
            :mark {:type "bar" :tooltip true}
            :encoding {:x {:field "severity" :type "nominal"
                           :title (theme/severity-title :severity)
                           :sort (:severity-order @(resolve 'vulcan.analysis.categorize/defaults))}
                       :y {:field "n" :type "quantitative"
                           :title (theme/severity-title :n)}
                       :color (vl-color "severity" theme/severity-colors sevs)}})

       (plotly-fig [(-> (bar-trace sevs ns nil nil)
                        (assoc :marker {:color (mapv theme/severity-colors sevs)}))]
                   title)))))

;; ---------------------------------------------------------------------------
;; 2. severity-by-artifact

(defn severity-by-artifact
  "Stacked bars per artifact, sorted by total findings so the worst image is
  first and the eye does not have to search for it."
  ([x] (severity-by-artifact x {}))
  ([x opts]
   (let [ds    (ctx->findings x)
         title (:title opts "Findings by artifact and severity")]
     (if (zero? (tc/row-count ds))
       (severity-bars ds opts)
       (let [grouped (-> ds
                         (tc/group-by [:artifact-name :severity])
                         (tc/aggregate {:n tc/row-count}))
             totals  (into {} (map (juxt :artifact-name :n))
                           (-> ds (tc/group-by [:artifact-name])
                               (tc/aggregate {:n tc/row-count})
                               (tc/rows :as-maps)))
             order   (->> (sort-by (comp - totals) (keys totals)) vec)
             sevs    (vec (distinct (:severity grouped)))]
         (case (target-of opts)
           :vega-lite
           (vl (assoc opts :title title)
               {:data (vl-values grouped [:artifact-name :severity :n])
                :mark {:type "bar" :tooltip true}
                :encoding {:y {:field "artifact-name" :type "nominal"
                               :title (theme/severity-title :artifact-name)
                               :sort order}
                           :x {:field "n" :type "quantitative" :stack "zero"
                               :title (theme/severity-title :n)}
                           :color (vl-color "severity" theme/severity-colors sevs)}})

           (plotly-fig
            (for [sev (theme/ordered-domain theme/severity-colors sevs)
                  :let [rows (->> (tc/rows grouped :as-maps)
                                  (filter #(= sev (:severity %)))
                                  (map (juxt :artifact-name :n))
                                  (into {}))]]
              (-> (bar-trace (mapv #(get rows % 0) order) order sev
                             (theme/severity-colors sev))
                  (assoc :orientation "h")))
            title)))))))

;; ---------------------------------------------------------------------------
;; 3. exploitability-matrix

(defn exploitability-matrix
  "Severity x exploitability heatmap: the two axes that together decide
  urgency, crossed, so the top-left cell is the work that cannot wait."
  ([x] (exploitability-matrix x {}))
  ([x opts]
   (let [ds    (ctx->findings x)
         title (:title opts "Severity by exploitability")]
     (if (zero? (tc/row-count ds))
       (vl (assoc opts :title title) {:data {:values []} :mark "rect" :encoding {}})
       (let [grouped (-> ds
                         (tc/group-by [:severity :exploitability])
                         (tc/aggregate {:n tc/row-count}))
             sev-order (theme/ordered-domain theme/severity-colors (:severity grouped))
             exp-order (theme/ordered-domain theme/exploitability-colors
                                             (:exploitability grouped))]
         (case (target-of opts)
           :vega-lite
           (vl (assoc opts :title title)
               {:data (vl-values grouped [:severity :exploitability :n])
                :mark {:type "rect" :tooltip true}
                :encoding {:y {:field "severity" :type "nominal" :sort sev-order
                               :title (theme/severity-title :severity)}
                           :x {:field "exploitability" :type "nominal" :sort exp-order
                               :title (theme/severity-title :exploitability)}
                           :color {:field "n" :type "quantitative"
                                   :title (theme/severity-title :n)
                                   :scale {:range theme/sequential}}}})

           (let [cell (into {} (map (juxt (juxt :severity :exploitability) :n))
                            (tc/rows grouped :as-maps))
                 z    (vec (for [s sev-order]
                             (vec (for [e exp-order] (get cell [s e] 0)))))]
             ^{:kindly/kind :kind/plotly}
             {:data [{:type "heatmap" :x exp-order :y sev-order :z z
                      :colorscale (vec (map-indexed
                                        (fn [i c]
                                          [(double (/ i (dec (count theme/sequential)))) c])
                                        theme/sequential))
                      :hovertemplate "%{y} / %{x}: %{z}<extra></extra>"}]
              :layout (theme/plotly-layout title)})))))))

;; ---------------------------------------------------------------------------
;; 4. fix-first-table

(defn fix-first-table
  "The ranked fix list. A table, not a chart: the deliverable is a list of
  things to do, and a bar chart of 20 scores is a worse list.

  Returns a dataset; `vulcan.report.kinds/table` renders it as an HTML table
  or a Markdown one depending on the profile."
  ([x] (fix-first-table x {}))
  ([x opts]
   (let [scored (if (and (map? x) (contains? x :scored)) (:scored x) x)
         n      (:top-n opts 20)]
     (-> (core/top-findings scored n)
         (tc/set-dataset-name "fix-first")))))

;; ---------------------------------------------------------------------------
;; 5. trend-lines

(defn trend-lines
  "Findings over time by severity. One line per severity, all artifacts
  summed, because the management question is \"is the total going down\"."
  ([x] (trend-lines x {}))
  ([x opts]
   (let [trend-ds (if (and (map? x) (contains? x :trend)) (:trend x) x)
         title    (:title opts "Findings over time")]
     (if (zero? (tc/row-count trend-ds))
       (vl (assoc opts :title title) {:data {:values []} :mark "line" :encoding {}})
       (let [summed (-> trend-ds
                        (tc/group-by [:created-at :severity])
                        (tc/aggregate {:n #(reduce + (:n %))})
                        (tc/map-columns :date [:created-at] str)
                        (tc/order-by [:created-at]))
             sevs   (vec (distinct (:severity summed)))]
         (case (target-of opts)
           :vega-lite
           (vl (assoc opts :title title)
               {:data (vl-values summed [:date :severity :n])
                :mark {:type "line" :point true :tooltip true}
                :encoding {:x {:field "date" :type "temporal"
                               :title (theme/severity-title :created-at)}
                           :y {:field "n" :type "quantitative"
                               :title (theme/severity-title :n)}
                           :color (vl-color "severity" theme/severity-colors sevs)}})

           (plotly-fig
            (for [sev (theme/ordered-domain theme/severity-colors sevs)
                  :let [rows (->> (tc/rows summed :as-maps)
                                  (filter #(= sev (:severity %)))
                                  (sort-by :created-at))]]
              {:type "scatter" :mode "lines+markers" :name sev
               :x (mapv :date rows) :y (mapv :n rows)
               :line {:color (theme/severity-colors sev)}})
            title)))))))

;; ---------------------------------------------------------------------------
;; 6. diff-waterfall

(defn diff-waterfall
  "What changed since the previous scan, as counts per change label."
  ([x] (diff-waterfall x {}))
  ([x opts]
   (let [diff-ds (if (and (map? x) (contains? x :diff)) (:diff x) x)
         summary (diff/summary diff-ds)
         title   (:title opts "Change since previous scan")
         changes (vec (:change summary))
         ns      (vec (:n summary))]
     (case (target-of opts)
       :vega-lite
       (vl (assoc opts :title title)
           {:data (vl-values summary [:change :n])
            :mark {:type "bar" :tooltip true}
            :encoding {:x {:field "change" :type "nominal"
                           :title (theme/severity-title :change)}
                       :y {:field "n" :type "quantitative"
                           :title (theme/severity-title :n)}
                       :color (vl-color "change" theme/change-colors changes)}})

       (plotly-fig [(-> (bar-trace changes ns nil nil)
                        (assoc :marker {:color (mapv #(theme/color-for
                                                       theme/change-colors % 0)
                                                     changes)}))]
                   title)))))

;; ---------------------------------------------------------------------------
;; 7. age-histogram

(defn age-histogram
  "How long findings have been public. A long tail is a process problem, not
  a technical one, and this is the chart that shows it."
  ([x] (age-histogram x {}))
  ([x opts]
   (let [ds    (ctx->findings x)
         title (:title opts "Age of findings")
         ages  (->> (:age-days ds) (remove nil?) (map long) vec)]
     (case (target-of opts)
       :vega-lite
       (vl (assoc opts :title title)
           {:data {:values (mapv (fn [a] {:age-days a}) ages)}
            :mark {:type "bar" :tooltip true}
            :encoding {:x {:field "age-days" :type "quantitative"
                           :bin {:maxbins 30}
                           :title (theme/severity-title :age-days)}
                       :y {:aggregate "count" :type "quantitative"
                           :title (theme/severity-title :n)}}})

       (plotly-fig [{:type "histogram" :x ages :nbinsx 30
                     :marker {:color (theme/severity-colors "LOW")}}]
                   title)))))

;; ---------------------------------------------------------------------------
;; 8. package-pareto

(defn package-pareto
  "Cumulative share of findings by package, worst first. Answers \"how few
  upgrades clear most of the backlog\", which is the argument for doing them."
  ([x] (package-pareto x {}))
  ([x opts]
   (let [ds    (ctx->findings x)
         n     (:top-n opts 15)
         title (:title opts "Findings by package")]
     (if (zero? (tc/row-count ds))
       (vl (assoc opts :title title) {:data {:values []} :mark "bar" :encoding {}})
       (let [by-pkg (-> ds
                        (tc/group-by [:pkg-name])
                        (tc/aggregate {:n tc/row-count})
                        (tc/order-by [:n] [:desc])
                        (tc/head n))
             total  (reduce + (:n by-pkg))
             cum    (->> (:n by-pkg)
                         (reductions +)
                         (map #(* 100.0 (/ (double %) (double total))))
                         vec)
             pkgs   (vec (:pkg-name by-pkg))
             counts (vec (:n by-pkg))
             with-cum (tc/add-column by-pkg :cumulative-pct cum)]
         (case (target-of opts)
           :vega-lite
           (vl (assoc opts :title title)
               {:data (vl-values with-cum [:pkg-name :n :cumulative-pct])
                :layer [{:mark {:type "bar" :tooltip true :color (first theme/categorical)}
                         :encoding {:x {:field "pkg-name" :type "nominal" :sort pkgs
                                        :title (theme/severity-title :pkg-name)}
                                    :y {:field "n" :type "quantitative"
                                        :title (theme/severity-title :n)}}}
                        {:mark {:type "line" :point true :color (second theme/categorical)}
                         :encoding {:x {:field "pkg-name" :type "nominal" :sort pkgs}
                                    :y {:field "cumulative-pct" :type "quantitative"
                                        :title "Cumulative %"
                                        :axis {:orient "right"}}}}]
                :resolve {:scale {:y "independent"}}})

           ^{:kindly/kind :kind/plotly}
           {:data [(-> (bar-trace pkgs counts "Findings" (first theme/categorical)))
                   {:type "scatter" :mode "lines+markers" :name "Cumulative %"
                    :x pkgs :y cum :yaxis "y2"
                    :line {:color (second theme/categorical)}}]
            :layout (assoc (theme/plotly-layout title)
                           :yaxis2 {:overlaying "y" :side "right"
                                    :title "Cumulative %" :range [0 100]})}))))))

;; ---------------------------------------------------------------------------

(def all-charts
  "Every chart function, for the test that renders each to both targets."
  {:severity-bars         severity-bars
   :severity-by-artifact  severity-by-artifact
   :exploitability-matrix exploitability-matrix
   :trend-lines           trend-lines
   :diff-waterfall        diff-waterfall
   :age-histogram         age-histogram
   :package-pareto        package-pareto})
