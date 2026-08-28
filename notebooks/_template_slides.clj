;; TEMPLATE -- copy this file, do not require it (spec section 10.2).
;;
;;   bb new-notebook management/q3-review --kind slides
;;
;; The only difference from _template_report.clj is density: one idea per
;; `##`, few words, and no table longer than fits on a slide. The mechanism is
;; identical -- the same namespace still renders as HTML if asked, because the
;; profile decides representation, not content.

^{:kindly/hide-code true
  :clay {:title "Deck title"}}
(ns _template-slides
  (:require [scicloj.kindly.v4.kind :as kind]
            [vulcan.report.context :as ctx]
            [vulcan.report.kinds :as k]
            [vulcan.viz.charts :as charts]))

(def context (ctx/load!))

(kind/md "# Deck title")

(kind/md "## Where we stand")

(kind/md
 (format "- %d artifacts scanned\n- %d findings\n- %d CRITICAL, %d HIGH"
         (k/n context :n-artifacts)
         (k/n context :n-findings)
         (k/n context :n-critical)
         (k/n context :n-high)))

(kind/md "## Severity")

(k/chart context charts/severity-bars)

(kind/md "## Trend")

(k/chart context charts/trend-lines)

;; Prose that only makes sense when presented live.
(k/when-profile context #{:revealjs}
  (kind/md "::: {.notes}\nSpeaker notes go here.\n:::"))

(k/appendix context)
