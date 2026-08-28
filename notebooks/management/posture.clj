^{:kindly/hide-code true
  :clay {:title "Vulnerability posture"}}
(ns management.posture
  "The management view: a small number of stable KPIs, the trend, and the
  evidence trail.

  Deliberately short. The value of this notebook is that the same five
  numbers appear quarter after quarter and can be compared; adding to it is
  cheap and removing from it is not (spec section 8, `analysis.core/summary`)."
  (:require [scicloj.kindly.v4.kind :as kind]
            [tablecloth.api :as tc]
            [vulcan.report.context :as ctx]
            [vulcan.report.kinds :as k]
            [vulcan.viz.charts :as charts]))

(def context (ctx/load!))

(kind/md "# Vulnerability posture")

;; ---------------------------------------------------------------------------

(kind/md "## Headline")

(kind/md
 (format
  (str "- **%d artifacts** in scope\n"
       "- **%d findings**, **%d** distinct vulnerabilities\n"
       "- **%d CRITICAL**, **%d HIGH**\n"
       "- **%d** findings have a fix available\n"
       "- **%d** are known-exploited")
  (k/n context :n-artifacts)
  (k/n context :n-findings)
  (k/n context :n-vulns)
  (k/n context :n-critical)
  (k/n context :n-high)
  (k/n context :n-fixable)
  (k/n context :n-exploited)))

(k/when-profile context #{:pptx :revealjs}
  (kind/md
   (str "*Scope is the most recent scan of each artifact. Every number on "
        "this slide is derived from the scan ids listed at the end.*")))

;; ---------------------------------------------------------------------------

(kind/md "## Severity distribution")

(k/chart context charts/severity-bars)

;; ---------------------------------------------------------------------------

(kind/md "## Trend")

(kind/md
 (let [n-points (-> context :trend :scan-id distinct count)]
   (if (> n-points 1)
     (str "Findings over time across every scan in the store, not only those "
          "in the current scope -- a trend restricted to the current scope "
          "would not be one.")
     (str "Only one scan has been recorded so far, so there is no trend to "
          "show yet. This chart becomes meaningful from the second scan on."))))

(k/chart context charts/trend-lines)

;; ---------------------------------------------------------------------------

(kind/md "## Exposure and coverage")

(kind/md
 (let [pct (k/n context :pct-packages-affected)]
   (if pct
     (format
      (str "**%s** of the %d catalogued packages carry at least one finding "
           "(%d affected packages). The denominator exists because scans are "
           "run with `--list-all-pkgs`; without it this figure cannot be "
           "computed at all.")
      (k/pct pct)
      (k/n context :n-packages)
      (k/n context :n-affected-packages))
     (str "Package inventory is not available for these scans, so coverage "
          "cannot be expressed as a fraction. Re-run the scanner with "
          "`--list-all-pkgs` to enable it."))))

;; ---------------------------------------------------------------------------

(kind/md "## Fixability")

(kind/md
 (format
  (str "**%d** findings can be fixed today by upgrading. **%d** cannot: the "
       "vendor has declined them or the component is past end-of-life. That "
       "second number is carried deliberately rather than filtered out -- it "
       "is the part of the backlog that no amount of patching will clear.")
  (k/n context :n-fixable)
  (k/n context :n-declined)))

(k/chart context charts/severity-by-artifact)

;; ---------------------------------------------------------------------------

(kind/md "## Change since the previous scan")

(k/chart context charts/diff-waterfall)

(k/appendix context)
