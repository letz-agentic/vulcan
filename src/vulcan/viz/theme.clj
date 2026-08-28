(ns vulcan.viz.theme
  "One palette, applied to both chart targets (spec section 9.1).

  Severity colours are fixed and never chosen per chart: a reader who has
  learned that CRITICAL is dark red on the posture slide must not have to
  relearn it on the fix-first table. The ramp is monotonic in lightness as
  well as in hue, so it survives a greyscale print-out and the common forms of
  colour blindness -- severity is encoded twice, by hue and by darkness, and
  either channel alone is enough to read the order."
  (:require [clojure.string :as str]))

(def severity-colors
  "Ordered worst-first, and *monotonic in relative luminance*: CRITICAL is the
  darkest and UNKNOWN the lightest, with no crossings in between.

  That property, not the hue choice, is what makes the ramp readable. Severity
  is encoded twice -- by hue and by darkness -- so either channel alone
  suffices: the chart still reads when it is photocopied, projected badly, or
  seen by a reader with deuteranopia or protanopia, for whom the red/orange
  end collapses to a single hue and only the darkness separates the levels.

  `severity-palette-is-monotonic-in-lightness` enforces it, because this is
  exactly the property a well-meaning colour tweak breaks."
  {"CRITICAL" "#7f1d1d"
   "HIGH"     "#b91c1c"
   "MEDIUM"   "#d97706"
   "LOW"      "#38bdf8"
   "UNKNOWN"  "#cbd5e1"})

(def exploitability-colors
  "Same construction as `severity-colors`: darkest is most urgent."
  {"exploited" "#7f1d1d"
   "likely"    "#b91c1c"
   "possible"  "#d97706"
   "unlikely"  "#cbd5e1"})

(def fixability-colors
  {"fixable"         "#15803d"
   "pending"         "#b45309"
   "vendor-declined" "#64748b"
   "unknown"         "#cbd5e1"})

(def change-colors
  "Diff labels. Green is only ever 'this got better'."
  {"new"                "#b91c1c"
   "persisting"         "#b45309"
   "fixed-by-upgrade"   "#15803d"
   "disappeared"        "#0369a1"
   "no-longer-reported" "#64748b"
   "resolved"           "#15803d"})

(def categorical
  "For dimensions with no inherent order (artifacts, packages). Chosen for
  pairwise distinguishability rather than prettiness."
  ["#1f77b4" "#d95f02" "#7570b3" "#66a61e" "#e7298a"
   "#a6761d" "#666666" "#1b9e77" "#e6ab02" "#386cb0"])

(def sequential
  "Single-hue ramp for heatmap intensity. Light to dark, so 'more' is always
  'darker' regardless of how it is reproduced."
  ["#f1f5f9" "#cbd5e1" "#94a3b8" "#64748b" "#475569" "#1e293b"])

(def background "#ffffff")
(def font-family "Inter, Helvetica Neue, Helvetica, Arial, sans-serif")
(def font-size 12)

(defn color-for
  "Look up a fixed colour for a category value, falling back through the
  categorical palette so an unexpected value still plots."
  [palette value fallback-index]
  (or (get palette value)
      (nth categorical (mod fallback-index (count categorical)))))

(defn ordered-domain
  "The palette's own key order, restricted to values actually present. Passing
  an explicit domain keeps the legend order stable between two renders of the
  same chart even when one of them happens to have no CRITICAL findings."
  [palette present]
  (let [present (set present)]
    (vec (filter present (keys palette)))))

(defn range-for
  "The colour range matching `ordered-domain`."
  [palette present]
  (mapv palette (ordered-domain palette present)))

;; ---------------------------------------------------------------------------
;; target-specific styling

(defn plotly-layout
  "Layout defaults merged into every Plotly figure."
  [title]
  {:title       (when title {:text title :font {:size 16}})
   :font        {:family font-family :size font-size}
   :paper_bgcolor background
   :plot_bgcolor  background
   :margin      {:l 60 :r 20 :t (if title 50 20) :b 60}
   :legend      {:orientation "h" :y -0.2}})

(defn vega-config
  "Config block merged into every Vega-Lite spec. vl-convert renders these
  faithfully, so a static export and an interactive chart look the same."
  []
  {:background background
   :font       font-family
   :axis       {:labelFontSize font-size :titleFontSize font-size
                :labelColor "#334155" :titleColor "#0f172a"
                :grid true :gridColor "#e2e8f0"}
   :legend     {:labelFontSize font-size :titleFontSize font-size}
   :title      {:fontSize 16 :anchor "start" :color "#0f172a"}
   :view       {:stroke "transparent"}})

(defn severity-title
  "Human-facing axis titles, kept in one place so two charts cannot disagree
  about what a column is called."
  [k]
  (get {:severity         "Severity"
        :exploitability   "Exploitability"
        :fixability       "Fixability"
        :exposure         "Exposure"
        :artifact-name    "Artifact"
        :pkg-name         "Package"
        :n                "Findings"
        :n-findings       "Findings"
        :fix-first-score  "Fix-first score"
        :age-days         "Age (days)"
        :created-at       "Scan date"
        :change           "Change"}
       k
       (-> (name k) (str/replace "-" " ") str/capitalize)))
