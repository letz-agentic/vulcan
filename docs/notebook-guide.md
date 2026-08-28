# Writing a notebook

A notebook is a **view over a report context**. It receives the context from
one function and derives everything else. It never opens a connection, never
writes SQL, and never recomputes a KPI.

That is what makes "same data, many stories" true rather than aspirational:
one context, many renderings, and no way for the numbers to drift between
them.

```
bb new-notebook engineering/my-question
bb new-notebook management/q3-review --kind slides
```

## The seven rules

**1. Get the context once, at the top.**

```clojure
(def context (ctx/load!))
```

`load!` reads `VULCAN_DB`, `VULCAN_SCOPE` and `VULCAN_PROFILE` (or the
equivalent system properties, which is how `bb render` passes the profile in).
Never call `ctx/build` with your own connection in a notebook.

**2. Headings come from `kind/md`. `##` is a slide, `#` is a section.**

`slide-level` is fixed at 2 for every profile, so the same headings work as
document sections and as slides. Do not use `###` for something that should be
its own slide — it will not become one.

**3. Do not call `kind/plotly` or `kind/table` directly.**

Use `k/chart` and `k/table`. They pick the representation from the profile.
An interactive chart placed directly in a notebook is *invisible* in pptx and
PDF — Quarto drops raw HTML there, silently. `k/chart` renders a static image
for those profiles instead.

```clojure
(k/chart context charts/severity-bars)
(k/chart context charts/package-pareto {:top-n 15})
(k/table context (:by-package context) {:top-n 15})
```

**4. Profile-specific prose goes through `k/when-profile`, sparingly.**

```clojure
(k/when-profile context #{:pptx :revealjs}
  (kind/md "*Scope is the most recent scan of each artifact.*"))
```

If a notebook needs many of these, it is two notebooks.

**5. End with `(k/appendix context)`.**

It emits scan ids, store path, DuckDB version, enrichment cache age,
categorisation thresholds and score weights. Auditors need it; engineers
ignore it. Both outcomes are correct.

**6. Never type a number into prose.**

```clojure
;; no
(kind/md "We have 55 findings.")

;; yes
(kind/md (format "We have %d findings." (k/n context :n-findings)))
```

A typed number is a number that will be wrong next quarter. `k/n` reads from
`(:summary context)`, which is also what the charts are built from.

**7. Handle the empty case in prose.**

A store with one scan has no trend; a scope with no findings has no Pareto.
Say so rather than showing an empty chart with confident prose above it:

```clojure
(kind/md (if (> n-points 1)
           "Findings over time across every scan in the store."
           "Only one scan so far, so there is no trend yet."))
```

## What the context holds

| key           | what                                                        |
|---------------|-------------------------------------------------------------|
| `:meta`       | provenance: scan ids, scope, profile, thresholds, weights   |
| `:summary`    | the KPI map — the only source for numbers in prose          |
| `:findings`   | enriched findings, with the four categorisation axes        |
| `:scored`     | findings plus `:fix-first-score`, worst first               |
| `:by-package` | one row per upgrade — the engineering deliverable           |
| `:scans`      | scans in scope                                              |
| `:packages`   | package inventory (needs `--list-all-pkgs`)                 |
| `:diff`       | change vs each artifact's previous scan                     |
| `:trend`      | per-scan severity counts over **all** scans, long format    |

Findings carry enrichment (`:epss-score`, `:epss-percentile`, `:kev`,
`:sightings-count`, `:description`) and any active decision
(`:decision-status`, `:decision-justification`) as ordinary columns, because
`v_finding_enriched` has already joined them. A notebook never needs to know
that enrichment came from three different APIs.

If the store has not been enriched, every finding categorises as `unlikely` on
the exploitability axis. That is a real statement about what is known, and the
appendix reports the cache coverage so a reader can see it — but prose that
leans on exploitability should say so, as `engineering/fix_first` does.

## Rendering

```
bb render management/posture --profile revealjs
bb render management/posture --profile pptx
bb render --all --profile html
bb report --notebooks management/posture,engineering/fix_first --profiles html,pptx
```

Profiles: `html`, `revealjs`, `pptx`, `pdf`, `explore` (HTML with code shown).
