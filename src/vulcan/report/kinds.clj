(ns vulcan.report.kinds
  "The notebook vocabulary (spec sections 9.2, 10.1).

  A notebook says *what* it wants shown; this namespace decides *how*, from
  the report context's profile. That indirection is the whole mechanism behind
  \"same data, many stories\": one notebook renders as an interactive HTML
  report, as a reveal.js deck, and as a PowerPoint file, and the numbers
  cannot drift between them because there is only one context.

  The rule that makes it work: an interactive chart is invisible in pptx and
  PDF -- Quarto drops raw HTML there, with no error. So `chart` chooses Plotly
  for the screen profiles and a statically rendered image for the file
  profiles, and no notebook ever calls `kind/plotly` itself."
  (:require [clojure.string :as str]
            [scicloj.kindly.v4.kind :as kind]
            [tablecloth.api :as tc]
            [vulcan.viz.static :as static]))

(def interactive-profiles
  "Profiles whose output can host live JavaScript."
  #{:html :revealjs})

(def static-profiles
  "Profiles that Quarto renders through Pandoc, where raw HTML is discarded."
  #{:pptx :pdf})

(defn profile [ctx] (or (get-in ctx [:meta :profile]) :html))

(defn interactive? [ctx] (contains? interactive-profiles (profile ctx)))

;; ---------------------------------------------------------------------------
;; charts

(def ^:private renderer
  ;; One renderer per JVM: constructing it reads vulcan.edn.
  (delay (static/renderer)))

(def ^:private chart-counter (atom 0))

(def image-subdir
  "Where static chart PNGs are written, relative to the rendered `.qmd`.

  Our own directory rather than Clay's `<notebook>_files`, because we
  reference these images by a path that Quarto resolves relative to the qmd,
  and replicating Clay's target-naming rules to find its directory would be a
  guess that breaks the first time those rules change."
  "vulcan-charts")

(defn- image-dir
  "Absolute directory for static chart images, set by
  `vulcan.report.render/render!` to sit beside the generated qmd."
  []
  (or (System/getProperty "vulcan.image-dir")
      (str "target/reports/" image-subdir)))

(defn- static-chart
  "Render a chart to a PNG and reference it with plain Markdown.

  Deliberately *not* `kind/image`: Clay wraps that in a `::: {.clay-image}`
  fenced div, and Pandoc's pptx writer silently discards content inside a Div
  it does not recognise. The result is a slide with a heading and nothing
  under it -- the chart is gone, and nothing reports an error. A bare
  `![](path)` is what Pandoc turns into an actual picture on a slide."
  [ctx spec-fn opts]
  (let [spec (spec-fn ctx (assoc opts :target :vega-lite))
        n    (swap! chart-counter inc)
        name (format "chart-%03d.png" n)
        file (java.io.File. (image-dir) name)]
    (static/render-png-file! @renderer spec file)
    (kind/md (str "![](" image-subdir "/" name ")"))))

(defn chart
  "Render `spec-fn` against the context, choosing the representation from the
  profile (spec section 9.2).

      (k/chart ctx charts/severity-bars)
      (k/chart ctx charts/package-pareto {:top-n 10})

  For `:html` and `:revealjs` this is an interactive Plotly figure. For
  `:pptx` and `:pdf` the same chart is asked for its Vega-Lite form and
  rendered to a PNG by the pinned `vl-convert` binary, because an interactive
  figure would silently vanish from those outputs."
  ([ctx spec-fn] (chart ctx spec-fn {}))
  ([ctx spec-fn opts]
   (if (interactive? ctx)
     (kind/plotly (spec-fn ctx (assoc opts :target :plotly)))
     (static-chart ctx spec-fn opts))))

;; ---------------------------------------------------------------------------
;; tables

(defn- format-cell [v]
  (cond
    (nil? v)     ""
    (double? v)  (format "%.3f" v)
    (float? v)   (format "%.3f" v)
    (coll? v)    (str/join ", " v)
    :else        (str v)))

(defn- markdown-table
  "A dataset as a Markdown table. Pandoc turns this into a real PowerPoint
  table, which an HTML table would not become."
  [ds]
  (let [cols (vec (tc/column-names ds))
        head (str "| " (str/join " | " (map #(-> % name (str/replace "-" " ")) cols)) " |")
        sep  (str "|" (str/join "|" (repeat (count cols) "---")) "|")
        rows (for [row (tc/rows ds :as-maps)]
               (str "| " (str/join " | " (map #(format-cell (get row %)) cols)) " |"))]
    (str/join "\n" (concat [head sep] rows))))

(defn table
  "A dataset as a table, in the form the profile can actually display.

  Long tables are truncated to `:top-n` with a footnote rather than silently
  cut: a reader who cannot see that a list was shortened will read it as
  complete."
  ([ctx ds] (table ctx ds {}))
  ([ctx ds {:keys [top-n] :or {top-n 20}}]
   (let [total    (tc/row-count ds)
         shown    (min total top-n)
         trimmed  (tc/head ds shown)
         footnote (when (< shown total)
                    (format "\n\n*Showing the top %d of %d rows.*" shown total))]
     (if (interactive? ctx)
       (if footnote
         (kind/fragment [(kind/table trimmed) (kind/md footnote)])
         (kind/table trimmed))
       (kind/md (str (markdown-table trimmed) (or footnote "")))))))

;; ---------------------------------------------------------------------------
;; prose

(defn when-profile
  "Emit `content` only for the given profiles (spec section 10.1 rule 4).

  Returns an empty fragment rather than nil when the profile does not match:
  Clay renders a form's value, and a nil renders as the literal text `nil` in
  the middle of the report.

  Use sparingly. A notebook that needs many of these is two notebooks wearing
  a trench coat."
  [ctx profiles content]
  (if (contains? (set profiles) (profile ctx))
    content
    (kind/fragment [])))

(defn pct [x] (when x (format "%.1f%%" (double x))))

(defn n
  "A count from the summary, interpolated rather than typed (spec section 10.1
  rule 6), so prose and charts cannot disagree."
  [ctx k]
  (get-in ctx [:summary k]))

;; ---------------------------------------------------------------------------
;; the appendix

(defn- format-instant [t]
  (when t (str t)))

(defn- cache-line
  "How much of the store's enrichment is present, and how old it is.

  Reported per signal rather than as one number: EPSS and KEV come from bulk
  feeds and are usually complete, while CIRCL descriptions are rate-limited
  and often partial. A single combined count would understate the coverage
  that actually drives the exploitability axis."
  [{:keys [n-enriched n-total newest n-with-epss n-kev]}]
  (if (zero? (or n-total 0))
    (str "No enrichment data: EPSS, KEV and sightings were unavailable, so "
         "every finding is categorised `unlikely` on the exploitability axis.")
    (str (format "%d vulnerabilities in scope. " n-total)
         (when n-with-epss (format "EPSS: %d. " n-with-epss))
         (when n-kev (format "Known-exploited (KEV): %d. " n-kev))
         (format "Descriptions: %d. " (or n-enriched 0))
         (format "Newest enrichment %s." (or (format-instant newest) "unknown")))))

(defn appendix
  "The data-provenance section every notebook ends with (spec section 10.1
  rule 5).

  Auditors need it and engineers ignore it, which is the correct outcome for
  both. It carries what is required to reproduce the report exactly: the scan
  ids, the engine version, the enrichment cache age, and the thresholds and
  weights that produced the ranking."
  [ctx]
  (let [{:keys [generated-at db-path scope scan-ids cache-age thresholds
                weights duckdb profile]} (:meta ctx)]
    (kind/md
     (str/join
      "\n\n"
      ["## Data provenance"
       (format "Generated %s by Vulcan V, profile `%s`."
               (format-instant generated-at) (name (or profile :html)))
       (format "Store: `%s` (DuckDB %s). Scope: `%s`." db-path duckdb (pr-str scope))
       (cache-line cache-age)
       (format "Scans in this report (%d):" (count scan-ids))
       (str/join "\n" (map #(str "- `" % "`") scan-ids))
       "### Categorisation thresholds"
       (format "EPSS >= %s is `likely`; EPSS >= %s is `possible`."
               (:epss-likely thresholds) (:epss-possible thresholds))
       "### Fix-first weights"
       (str/join "\n" (for [[k v] (sort-by key weights)]
                        (format "- %s: %s" (name k) v)))]))))
