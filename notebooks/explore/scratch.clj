(ns explore.scratch
  "The REPL workbench (spec section 1, audience 3).

  Unlike the report notebooks, this one *shows* its code: the point is to try
  a question, not to publish an answer. A new question should be one `tc/`
  pipeline away and should never require touching ingestion."
  (:require [scicloj.kindly.v4.kind :as kind]
            [tablecloth.api :as tc]
            [vulcan.analysis.core :as core]
            [vulcan.analysis.score :as score]
            [vulcan.report.context :as ctx]
            [vulcan.report.kinds :as k]
            [vulcan.viz.charts :as charts]))

(def context (ctx/load!))

(kind/md "# Scratch")

(kind/md "## What is in scope")

(:summary context)

(kind/md "## The findings dataset")

(-> (:findings context) (tc/head 5))

(kind/md "## Example: worst packages by total score")

(-> (:by-package context)
    (tc/select-columns [:pkg-name :fixed-version :n-findings :total-score])
    (tc/head 10)
    kind/table)

(kind/md "## Example: severity by exposure")

(-> (:findings context)
    (tc/group-by [:exposure :severity])
    (tc/aggregate {:n tc/row-count})
    (tc/order-by [:exposure :severity])
    kind/table)

(kind/md "## Example: a chart")

;; Even here, charts go through `k/chart` rather than `kind/plotly`: a chart
;; placed directly would be silently dropped if this notebook were ever
;; rendered to pptx or PDF. To inspect the raw spec instead, ask a chart
;; function for one -- `(charts/severity-bars context {:target :vega-lite})`.
(k/chart context charts/severity-bars)
