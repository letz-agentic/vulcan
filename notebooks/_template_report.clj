;; TEMPLATE -- copy this file, do not require it (spec section 10.2).
;;
;;   bb new-notebook engineering/my-question
;;
;; A notebook is a *view* over a report context. It receives the context from
;; one function and derives everything else; it never opens a connection and
;; never writes SQL. That is what lets the same namespace render as an HTML
;; report and as a slide deck from numbers that cannot disagree.
;;
;; Conventions (spec section 10.1):
;;   1. get the context from `ctx/load!`, once, at the top
;;   2. headings come from `kind/md`; `##` is a slide, `#` is a section
;;   3. code is hidden in report profiles via the ns-level :kindly/hide-code
;;   4. profile-specific prose goes through `k/when-profile`, sparingly
;;   5. end with `(k/appendix ctx)`
;;   6. never type a number into prose -- interpolate it from `(:summary ctx)`

^{:kindly/hide-code true
  :clay {:title "Report title"}}
(ns _template-report
  (:require [scicloj.kindly.v4.kind :as kind]
            [vulcan.report.context :as ctx]
            [vulcan.report.kinds :as k]
            [vulcan.viz.charts :as charts]))

(def context (ctx/load!))

(kind/md "# Report title")

(kind/md
 (format "Across %d artifacts we are carrying %d findings, of which %d are CRITICAL."
         (k/n context :n-artifacts)
         (k/n context :n-findings)
         (k/n context :n-critical)))

;; ## A section, or a slide

(kind/md "## Severity")

(k/chart context charts/severity-bars)

(kind/md "## What to fix first")

(k/table context (charts/fix-first-table context {:top-n 10}) {:top-n 10})

;; Every notebook ends with the provenance section.
(k/appendix context)
