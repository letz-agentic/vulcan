^{:kindly/hide-code true
  :clay {:title "Fix first"}}
(ns engineering.fix-first
  "The engineering deliverable: what to fix, in what order, and why.

  One question per section. The ordering comes from the fix-first score
  (spec section 8.3), whose weights are printed in the appendix so that a
  reader who disagrees with the ranking can see exactly what produced it."
  (:require [scicloj.kindly.v4.kind :as kind]
            [tablecloth.api :as tc]
            [vulcan.analysis.core :as core]
            [vulcan.report.context :as ctx]
            [vulcan.report.kinds :as k]
            [vulcan.viz.charts :as charts]))

(def context (ctx/load!))

(kind/md "# Fix first")

(kind/md
 (format
  (str "This is the current posture across **%d artifacts**: **%d findings** "
       "covering **%d distinct vulnerabilities**, of which **%d** have a fix "
       "available today and **%d** have been declined by the vendor or are "
       "past end-of-life.")
  (k/n context :n-artifacts)
  (k/n context :n-findings)
  (k/n context :n-vulns)
  (k/n context :n-fixable)
  (k/n context :n-declined)))

;; ---------------------------------------------------------------------------

(kind/md "## What to fix first")

(kind/md
 (str "Ranked by the composite fix-first score: severity, exploitability, "
      "whether a fix exists, how many artifacts are affected, and age. "
      "Ties break toward the finding that touches more artifacts, because "
      "one upgrade that clears several images is worth more than one that "
      "clears one."))

(k/table context (charts/fix-first-table context {:top-n (get-in context [:meta :top-n])})
         {:top-n (get-in context [:meta :top-n])})

;; ---------------------------------------------------------------------------

(kind/md "## Fix by package")

(kind/md
 (str "The same backlog grouped by the upgrade that clears it. This is the "
      "list to work from: each row is one version bump."))

(k/table context
         (-> (:by-package context)
             (tc/select-columns [:pkg-name :fixed-version :worst-severity
                                 :n-findings :n-artifacts :artifacts :total-score]))
         {:top-n 15})

;; ---------------------------------------------------------------------------

(kind/md "## Where the findings are concentrated")

(k/chart context charts/package-pareto {:top-n 15})

;; ---------------------------------------------------------------------------

(kind/md "## Severity by artifact")

(k/chart context charts/severity-by-artifact)

;; ---------------------------------------------------------------------------

(kind/md "## Urgency: severity against exploitability")

(kind/md
 (let [n-exploited (k/n context :n-exploited)]
   (if (pos? n-exploited)
     (format (str "**%d findings are known-exploited** (in CISA KEV or with "
                  "observed sightings). Those are the top-left cells and they "
                  "come before everything else.")
             n-exploited)
     (str "No finding in this scope is known-exploited. Note that this is only "
          "as current as the enrichment cache -- see the appendix for its age."))))

(k/chart context charts/exploitability-matrix)

;; ---------------------------------------------------------------------------

(kind/md "## What changed since the last scan")

(kind/md
 (let [n-diff (tc/row-count (:diff context))]
   (if (pos? n-diff)
     (str "Comparing each artifact against its own previous scan. `resolved` "
          "is split by cause: a package upgraded past its findings is "
          "progress, a package that vanished from the image may not be.")
     (str "No artifact in this scope has been scanned more than once yet, so "
          "there is nothing to compare against."))))

(k/chart context charts/diff-waterfall)

;; ---------------------------------------------------------------------------

(kind/md "## How old is this backlog")

(kind/md
 (let [median (k/n context :median-age-days)]
   (if median
     (format (str "Median age at scan time is **%.0f days**. A long right tail "
                  "is a process signal rather than a technical one.")
             (double median))
     "No publication dates were available for these findings.")))

(k/chart context charts/age-histogram)

;; ---------------------------------------------------------------------------

(kind/md "## Fixability breakdown")

(k/table context (core/axis-counts (:findings context) :fixability) {:top-n 10})

(k/appendix context)
