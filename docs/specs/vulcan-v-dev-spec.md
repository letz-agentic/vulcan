# Vulcan V — Development Specification

**Vulnerability categorization, analysis and visualization — in Clojure**

Version 0.1 (draft) · 28 August 2026 · Author: Tudor Ștefănescu (drafted with Claude)

---

## 0. Reading guide

This document is a *development* spec, not a product brochure. It fixes the decisions that are expensive to change later (data model, storage, notebook conventions), leaves open what is cheap to change (chart styling, score weights), and states for every non-obvious choice the alternative that was considered and why it lost. Sections 1–3 are the "why"; 4–9 are the "what"; 10–13 are the "how we will know it works".

Every external fact (library versions, Trivy schema, API endpoints) was checked against the primary source on the date above; the references in §14 are the ones to re-check before pinning versions.

---

## 1. Purpose and intended use

Vulcan V consolidates the earlier lab-file work (Trivy JSON → tablecloth analytics, CIRCL Vulnerability-Lookup enrichment with EDN caching, tableplot/Plotly charts, composite "fix-first" score, Clay→Quarto rendering) into a structured, versioned library with one canonical data store and reproducible report pipelines.

It serves three audiences from one data layer:

1. **Engineering / platform teams** — "what do we fix first, per image and per repository, and what changed since last week." Output: ranked fix lists, per-target drill-downs, diffs between scans.
2. **Management / compliance** — posture and trend evidence for NIS2/DORA-style vulnerability-management obligations, design reviews and audits. Output: slide decks (reveal.js for live presentation, pptx for the corporate circuit, PDF for the record) with a small number of stable KPIs.
3. **The author at the REPL** — an exploration workbench where a new question is one `tc/` pipeline away and never requires touching the ingestion code.

### 1.1 Non-goals (v1)

Vulcan V is not a scanner (Trivy is), not a ticketing system, not a multi-user web application, and not a policy engine that decides what is acceptable. It reads scan output, stores it, enriches it, analyses it and renders it. Multi-scanner support (Grype, Syft SBOMs) is deliberately excluded from v1 but the data model must not preclude it (see §5.6).

### 1.2 Guiding principles

**Local-first.** Everything runs from a single DuckDB file and a `deps.edn`; no service, no container, no daemon. Rendering must work offline once dependencies are cached.

**REPL-driven.** Every stage (ingest, enrich, analyse, chart) is a pure-ish function over data that can be called interactively; notebooks are ordinary namespaces that are also evaluable top to bottom.

**Data as values.** Trivy JSON is parsed into plain Clojure maps, normalised into tablecloth datasets, persisted into DuckDB tables. The analysis layer never reads JSON; the notebook layer never runs SQL it did not get from the analysis layer.

**Supply-chain hygiene.** Every dependency is pinned by version (and, for Quarto, by checksum); the build is reproducible from a clean checkout without network access at render time. This matters because the outputs feed security decisions and will be shown to auditors.

**Same data, many stories.** A notebook is a *view* over a *report context*; the report context is built once per data snapshot and shared by every notebook and every output format.

---

## 2. Architecture overview

```
 Trivy JSON  ──► ingest ──► DuckDB (canonical store) ◄── enrich (CIRCL VL: EPSS, KEV, sightings)
 (files/dirs)     │                 │
                  │                 ▼
                  │            analysis (tablecloth datasets, scores, diffs, trends)
                  │                 │
                  │                 ▼
                  │            viz (tableplot specs; Vega-Lite / Plotly; static SVG/PNG)
                  │                 │
                  ▼                 ▼
             notebooks (Clay + Kindly) ──► Quarto ──► HTML report | reveal.js | pptx | PDF
```

Layers and their namespaces:

| Layer | Namespace prefix | Depends on | Must not depend on |
|---|---|---|---|
| Common | `vulcan.common` | jsonista | nothing (shared utilities) |
| Ingestion | `vulcan.ingest.*` | common, jsonista, malli | tableplot, Clay |
| Store | `vulcan.store.*` | next.jdbc, DuckDB, HoneySQL, tablecloth | ingest, enrich, analysis, viz, notebooks |
| Enrichment | `vulcan.enrich.*` | common, hato/http, store | ingest, viz, notebooks |
| Analysis | `vulcan.analysis.*` | tablecloth, store | viz, notebooks |
| Visualization | `vulcan.viz.*` | tableplot, analysis | notebooks |
| Reporting | `vulcan.report.*` + `notebooks/` | Clay, Kindly, viz, analysis | nothing depends on these |
| CLI | `vulcan.cli` (+ `bb.edn` tasks) | all | — |

Note: The store layer returns tablecloth datasets directly from queries, which simplifies the API between store and analysis. This is an intentional design choice — see ADR 0002.

The dependency direction is enforced by a test (`vulcan.arch-test`) that scans `ns` forms; this is cheap and prevents the lab-file entropy from returning.

---

## 3. Stack decisions (with alternatives)

| Concern | Decision | Considered | Why |
|---|---|---|---|
| Language/runtime | Clojure 1.12, JDK 21 LTS | — | Existing tooling; Emacs/CIDER workflow |
| Canonical store | **DuckDB** via `org.duckdb/duckdb_jdbc` **1.5.5.1** (Aug 2026) | SQLite; Datalevin; plain Parquet + tablecloth | Columnar analytics, native JSON/Parquet, single file, zero ops; SQLite lacks the analytic performance and JSON ergonomics; Datalevin would be elegant for the CVE graph but adds a second query language for no v1 benefit |
| DB access | `next.jdbc` + HoneySQL 2 for composed queries; raw SQL strings for the ingestion DDL | tmducken (FFI), `tech.ml.dataset.sql` | JDBC is the driver the DuckDB team ships and tests; `result-set->dataset` from `tech.ml.dataset.sql` is used *only* for the ResultSet→dataset hop, not for its connection utilities (PostgreSQL-oriented). tmducken's maintenance status is not verified — revisit if JDBC throughput becomes a bottleneck |
| JSON parsing | `jsonista` | data.json, cheshire, DuckDB `read_json` | Fast, Jackson-based, keyword keys; DuckDB `read_json` kept as an *ad-hoc* escape hatch (see §6.4) |
| Dataset layer | **tablecloth 8.024** (Aug 2026) | raw tech.ml.dataset | Existing lab code; expressive pipelines |
| Charts | **tableplot 1-beta17** (Apr 2026) with Plotly target for HTML and Vega-Lite target for static export | Hanami direct; Oz; ECharts hiccup | tableplot builds on tablecloth datasets directly; two targets cover interactive and static |
| Static rendering (pptx/PDF) | Vega-Lite → SVG/PNG via the **`vl-convert` CLI** (self-contained Rust binary embedding V8/Deno, no Node or browser, offline), pinned by version and checksum | `applied-science/darkstar` (in-JVM GraalJS); headless Chromium; Python kaleido | darkstar would have been the cleanest (pure JVM dependency) but bundles Vega-Lite 4.10.1, which is two major versions behind what tableplot emits; vl-convert tracks current Vega-Lite (5.x) and is a single checksummed binary — acceptable under the supply-chain rule |
| Notebooks | **Clay 2.0.21** (Aug 2026) + Kindly | Clerk | Clay emits Quarto markdown natively and supports `[:quarto :revealjs]`; Clerk would need a separate slide path |
| Rendering | **Quarto** (pinned, checksummed) → html, revealjs, pptx (via `reference-doc`), pdf | Pandoc direct | Quarto is what Clay targets; pptx `reference-doc` gives the corporate template |
| HTTP | `hato` (JDK HttpClient) | clj-http | No Apache stack; small footprint |
| Validation | Malli schemas for Trivy report, report context, chart specs | clojure.spec | Data-driven, generates test data, produces readable errors for malformed Trivy files |
| Scripting/CLI | Babashka tasks (`bb.edn`) delegating to `clojure -M` | tools.build only | Fast task entry; `bb` for glue, JVM for the work |
| Tests | clojure.test + test.check; Kaocha runner | — | Property tests for the score and for ingestion idempotency |

---

## 4. Repository layout

```
vulcan-v/
├── deps.edn                 ; pinned deps, aliases: :dev :test :notebooks :cli
├── bb.edn                   ; tasks: ingest, enrich, render, report, check
├── clay.edn                 ; Clay defaults (source paths, quarto options)
├── README.md
├── doc/
│   ├── spec.md              ; this document
│   ├── adr/                 ; one ADR per decision in §3 (0001-duckdb.md, ...)
│   ├── notebook-guide.md    ; how to write a notebook (see §9)
│   └── schema.md            ; generated from the DDL
├── resources/
│   ├── sql/                 ; DDL + migrations (0001_init.sql, ...)
│   ├── quarto/              ; _quarto.yml fragments, theme.scss, reference.pptx
│   └── fixtures/trivy/      ; small real-world JSON reports (anonymised)
├── src/vulcan/
│   ├── common.clj           ; shared utilities (JSON, hashing, time parsing)
│   ├── ingest/{trivy,json,dir,schema}.clj
│   ├── store/{db,migrate,write,query}.clj
│   ├── enrich/{provider,http,circl,cache,epss,kev,vex}.clj
│   ├── analysis/{core,score,categorize,diff,trend}.clj
│   ├── viz/{theme,charts,static}.clj
│   ├── report/{context,kinds,render}.clj
│   └── cli.clj
├── notebooks/
│   ├── _template_report.clj
│   ├── _template_slides.clj
│   ├── engineering/fix_first.clj
│   ├── management/posture.clj
│   └── explore/scratch.clj
├── test/vulcan/...
└── data/                    ; git-ignored: vulcan.duckdb, raw/, cache/
```

---

## 5. Data model (DuckDB)

### 5.1 Design rules

The store is *append-only with idempotent upsert*: re-ingesting the same file is a no-op; ingesting a new scan of the same artifact adds a new `scan` row and new `finding` rows, never mutates old ones. This gives trend analysis for free and makes every report reproducible by `scan_id`.

Identity is content-derived, not sequence-derived. `scan_id` is a SHA-256 of the raw report bytes (so the same file from two directories is the same scan); `finding_id` is a hash of `(scan_id, target, vulnerability_id, pkg_id, installed_version)`. Sequence ids are avoided so that two DuckDB files ingested independently can be merged with `INSERT ... ON CONFLICT DO NOTHING`.

Provenance is a first-class column: every row knows which file, which Trivy version and which DB version produced it, because auditors ask.

### 5.2 Tables

```sql
-- One row per ingested report file
CREATE TABLE scan (
  scan_id          VARCHAR PRIMARY KEY,   -- sha256 of report bytes
  schema_version   INTEGER NOT NULL,      -- Trivy SchemaVersion (2)
  created_at       TIMESTAMP NOT NULL,    -- report CreatedAt
  ingested_at      TIMESTAMP NOT NULL,
  artifact_name    VARCHAR NOT NULL,      -- e.g. registry/app:1.2.3
  artifact_type    VARCHAR NOT NULL,      -- container_image | filesystem | repository | ...
  image_id         VARCHAR,               -- Metadata.ImageID
  repo_digests     VARCHAR[],             -- Metadata.RepoDigests
  os_family        VARCHAR, os_name VARCHAR, os_eosl BOOLEAN,
  trivy_version    VARCHAR,               -- from Metadata or CLI wrapper
  source_file      VARCHAR NOT NULL,
  raw              JSON                   -- full report, for anything we forgot
);

-- One row per Results[] entry
CREATE TABLE target (
  target_id   VARCHAR PRIMARY KEY,        -- hash(scan_id, target, class, type)
  scan_id     VARCHAR NOT NULL REFERENCES scan(scan_id),
  target      VARCHAR NOT NULL,           -- "alpine:3.19 (alpine 3.19.1)" / "app/go.sum"
  class       VARCHAR NOT NULL,           -- os-pkgs | lang-pkgs | config | secret | license
  type        VARCHAR                     -- alpine | gobinary | jar | ...
);

-- One row per Vulnerabilities[] entry (the fact table)
CREATE TABLE finding (
  finding_id         VARCHAR PRIMARY KEY,
  scan_id            VARCHAR NOT NULL REFERENCES scan(scan_id),
  target_id          VARCHAR NOT NULL REFERENCES target(target_id),
  vulnerability_id   VARCHAR NOT NULL,    -- CVE-..., GHSA-..., ...
  pkg_id             VARCHAR,             -- PkgID
  pkg_name           VARCHAR NOT NULL,
  purl               VARCHAR,             -- PkgIdentifier.PURL
  installed_version  VARCHAR NOT NULL,
  fixed_version      VARCHAR,             -- may be a comma-separated list
  status             VARCHAR NOT NULL,    -- see §5.3
  severity           VARCHAR NOT NULL,    -- UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL (Trivy-selected)
  severity_source    VARCHAR,             -- nvd | redhat | ghsa | ...
  cvss               JSON,                -- full CVSS map keyed by source
  cvss_v3_score      DOUBLE,              -- best available V3 base score (derived)
  cvss_v3_vector     VARCHAR,
  cwe_ids            VARCHAR[],
  published_date     TIMESTAMP,
  last_modified_date TIMESTAMP,
  layer_digest       VARCHAR, layer_diff_id VARCHAR,
  data_source        JSON,
  title              VARCHAR,
  refs               VARCHAR[]
);

-- Vulnerability dimension (one row per ID, enriched; independent of scans)
CREATE TABLE vulnerability (
  vulnerability_id  VARCHAR PRIMARY KEY,
  description       VARCHAR,
  epss_score        DOUBLE, epss_percentile DOUBLE, epss_date DATE,
  kev               BOOLEAN DEFAULT FALSE, kev_date_added DATE, kev_ransomware BOOLEAN,
  sightings_count   INTEGER,
  circl_fetched_at  TIMESTAMP,
  circl_raw         JSON
);

-- Human decisions: VEX-like statements and time-boxed exceptions
CREATE TABLE decision (
  decision_id       VARCHAR PRIMARY KEY,
  vulnerability_id  VARCHAR NOT NULL,
  scope             VARCHAR NOT NULL,     -- purl | artifact_name | '*' pattern
  status            VARCHAR NOT NULL,     -- not_affected | affected | fixed | under_investigation (OpenVEX)
  justification     VARCHAR,              -- OpenVEX justification enum
  note              VARCHAR,
  decided_by        VARCHAR, decided_at TIMESTAMP,
  expires_at        TIMESTAMP,
  source            VARCHAR               -- 'manual' | 'openvex:<file>'
);

CREATE TABLE ingest_log (
  scan_id VARCHAR, source_file VARCHAR, ingested_at TIMESTAMP,
  outcome VARCHAR,  -- inserted | duplicate | rejected
  message VARCHAR
);
```

### 5.3 Trivy status vocabulary

`finding.status` uses Trivy's own eight values so that the store and the scanner agree: `unknown`, `not_affected`, `affected`, `fixed`, `under_investigation`, `will_not_fix`, `fix_deferred`, `end_of_life`. `--ignore-unfixed` in Trivy is equivalent to keeping only `fixed`; Vulcan V never applies that filter at ingestion (the analysis layer does, explicitly, so that the "unfixable" backlog remains visible to management).

### 5.4 Views

Views are the contract between store and analysis; notebooks query views, never base tables:

- `v_finding_enriched` — `finding ⋈ target ⋈ scan ⋈ vulnerability` with derived columns `is_fixable`, `age_days` (from `published_date`), `exploited` (KEV or sightings), and the active `decision` if any.
- `v_latest_scan_per_artifact` — window function over `scan` picking the newest `created_at` per `artifact_name`; the default scope for "current posture".
- `v_scan_summary` — counts by severity/status per scan, for trend lines.

### 5.5 Migrations

`resources/sql/NNNN_*.sql` applied in order by `vulcan.store.migrate`, recorded in a `schema_migration` table. DuckDB's storage format has changed across major versions; the migration tool records the DuckDB version and refuses to open a file written by a newer driver.

### 5.6 Multi-scanner readiness

`scan.scanner` (default `'trivy'`) and `finding.scanner_native` (JSON) are added in migration 0002 as nullable columns so Grype/SBOM ingestion can land later without renumbering identities.

---

## 6. Ingestion

### 6.1 Inputs

Trivy JSON reports, schema version 2 (the current format; there is a long-standing request to document it formally, so the *fixtures* in `resources/fixtures/trivy/` are the practical contract). Sources: a file, a directory (recursive, glob `**/*.json`), or stdin. Reports from `trivy image`, `trivy fs`, `trivy repo`, `trivy sbom` and `trivy k8s` (per-workload JSON) are accepted; `trivy convert` output is identical in shape.

Recommended scanner invocation for maximum downstream value (documented in the README, not enforced):

```
trivy image --format json --list-all-pkgs --scanners vuln \
  --output reports/$(date -u +%Y%m%dT%H%M%SZ)_app.json registry/app:1.2.3
```

`--list-all-pkgs` matters: without it, Trivy only emits packages that have findings, so "fraction of packages affected" is impossible to compute later.

### 6.2 Pipeline

```
read bytes → sha256 → duplicate? → parse (jsonista) → validate (Malli, SchemaVersion=2)
  → normalise to row maps {scan, targets, findings, packages}
  → single transaction: INSERT scan, targets, findings ON CONFLICT DO NOTHING
  → ingest_log row
```

`vulcan.ingest.trivy/report->rows` is a pure function from parsed JSON to `{:scan m :targets [..] :findings [..]}` and is the unit under test. The DB write is a separate function taking a connection. Batch inserts use `next.jdbc/execute-batch!` with prepared statements; for large directories (thousands of reports) the alternative is DuckDB's Appender API through the JDBC driver (`DuckDBConnection.createAppender`) — measured before adopting.

Derived columns computed at ingest time: `cvss_v3_score` (prefer `nvd` V3, else the source Trivy chose for severity, else max across sources); `layer_*` flattened; `refs` and `cwe_ids` as arrays.

### 6.3 Failure policy

A malformed report is rejected as a whole, logged in `ingest_log`, and the run continues with the next file; the exit code reflects any rejection. A report with `SchemaVersion ≠ 2` is rejected with a message naming the version. A report with zero `Results` is still recorded as a scan (that is evidence of a clean image, which management wants to see).

### 6.4 The DuckDB-native alternative

DuckDB can load a report directly with `read_json('report.json', maximum_object_size = 268435456)` and unnest `Results` and `Vulnerabilities` in SQL. This was evaluated as the primary path and rejected for v1 because validation, schema-version handling and unit testing are markedly easier on Clojure maps, and because the `raw JSON` column already preserves the option. It stays as the documented route for one-off exploration (`vulcan.store.query/read-json-adhoc`) and as the likely optimisation if ingest throughput ever matters. The default `maximum_object_size` is 16 MiB; large `--list-all-pkgs` reports exceed it, hence the explicit parameter.

### 6.5 CLI

```
bb ingest  reports/                # directory or file(s); prints inserted/duplicate/rejected
bb ingest  --db data/other.duckdb  # target store
bb ingest  --dry-run               # parse + validate only
```

---

## 7. Enrichment

### 7.1 Source

CIRCL Vulnerability-Lookup (`https://vulnerability.circl.lu`): `GET /api/vulnerability/{id}` for description and cross-source data; `GET /api/cisa_kev/` for the KEV catalogue; `GET /api/sighting/?vuln_id=…` for exploitation sightings; `POST /api/exploit-hazard/batch` for EPSS-based hazard. Responses carry `RateLimit-*` headers; authentication is via the `X-API-KEY` header, set through the `CIRCL_API_KEY` environment variable. The instance's machine-readable policy at `/.well-known/api-policy.json` is authoritative for rate limits: 20 requests/minute anonymous, 40 with an API key.

An alternative is FIRST's EPSS CSV (daily bulk download, simpler to cache) — kept as a second `epss` provider behind the same protocol because it is bulk, offline-friendly and independent of CIRCL availability. The `Enricher` protocol has two methods: `(provider-name [this])` → keyword for logs and reports, and `(enrich [this ids])` → seq of maps. Providers are swappable and mockable.

### 7.2 Cache and freshness

The earlier file-backed EDN cache becomes the `vulnerability` table itself (`circl_raw`, `circl_fetched_at`). `bb enrich --max-age 7d` fetches only IDs missing or older than the threshold, with bounded concurrency (default 4) and exponential back-off on 429. `--offline` renders reports with whatever is cached and stamps the report with the cache age — reports must never fail because a public API is down.

### 7.3 Decisions / VEX

`decision` rows can be imported from an OpenVEX document (`bb decisions import vex.json`) and exported back (`bb decisions export`), which lets the same statements be fed to Trivy's `--vex` flag so scanner output and reports agree. Decisions are matched by `vulnerability_id` and a scope pattern over PURL or artifact name; expiry is honoured at analysis time.

---

## 8. Analysis

### 8.1 Entry point: the report context

```clojure
(ns vulcan.report.context)

(defn build
  "Everything a notebook needs, computed once. Pure over the store."
  [{:keys [db scope as-of]}]
  {:meta      {:generated-at .. :db-path .. :scope scope :cache-age ..}
   :scans     (ds ...)        ; scans in scope
   :findings  (ds ...)        ; v_finding_enriched in scope, decisions applied
   :packages  (ds ...)
   :summary   {...}           ; small map of KPIs (counts, medians)
   :scored    (ds ...)        ; findings with fix-first score and category
   :diff      (ds ...)        ; vs previous scan per artifact, when available
   :trend     (ds ...)})      ; v_scan_summary over time
```

`scope` is one of `:latest` (default; one scan per artifact), `{:artifacts [..]}`, `{:scan-ids [..]}` or `{:since inst}`. Notebooks receive the context and derive; they do not query.

### 8.2 Categorisation

Each finding is placed on four orthogonal axes, materialised as columns so that every chart can facet on them:

| Axis | Values | Source |
|---|---|---|
| Severity | CRITICAL … UNKNOWN | Trivy-selected `severity` |
| Exploitability | `exploited` (KEV or sightings) · `likely` (EPSS ≥ 0.1) · `possible` (EPSS ≥ 0.01) · `unlikely` | enrichment |
| Fixability | `fixable` (status=fixed & fixed_version present) · `vendor-declined` (will_not_fix, end_of_life, not_affected) · `pending` (affected, fix_deferred, under_investigation) · `unknown` | `status` |
| Exposure | `os` · `lang` · `config` · `secret` · `license` · `unknown` | `target.class` |

Thresholds are data in `vulcan.analysis.categorize/defaults`, overridable in the context options, and printed in every report's appendix.

### 8.3 Fix-first score

The composite from the lab work is kept but made explicit and unit-tested:

```
score = w_sev · sev(severity)            ; CRITICAL 1.0, HIGH .7, MEDIUM .4, LOW .1
      + w_exp · exp(epss, kev)           ; kev → 1.0 else epss percentile
      + w_fix · fix(fixability)          ; fixable 1.0, pending .3, declined 0
      + w_spread · spread(n_artifacts)   ; log-scaled count of affected artifacts in scope
      + w_age · age(published_date)      ; saturating at 365 days
```

Default weights (0.35, 0.30, 0.20, 0.10, 0.05) sum to 1. Property tests assert monotonicity (raising any input never lowers the score) and that a KEV CRITICAL fixable finding outranks everything without KEV. Rank is by score then by `n_artifacts` so that one upgrade fixing many images floats up — this "fix by package" view (`group-by [pkg_name fixed_version]`) is the engineering deliverable.

### 8.4 Diff and trend

`diff` compares the latest scan of each artifact with its previous one and labels findings:

- `new` — finding is in the current scan but not the previous
- `persisting` — finding is in both scans
- `fixed-by-upgrade` — package still installed but at a newer version that clears the finding
- `disappeared` — package is no longer in the artifact
- `no-longer-reported` — package is unchanged but the finding is no longer reported (advisory withdrawn or scope changed)
- `resolved` — fallback when `--list-all-pkgs` data is unavailable to distinguish the above

`trend` is `v_scan_summary` joined to time, with an optional weekly resample. Both are tablecloth datasets so they can be plotted directly.

---

## 9. Visualization

### 9.1 Toolkit

`vulcan.viz.charts` exposes a small, opinionated set of functions, each taking a dataset (or the context) and returning a tableplot layer map: `severity-bars`, `severity-by-artifact` (stacked, sorted), `exploitability-matrix` (severity × exploitability heatmap), `fix-first-table` (kind/table with sparkline of spread), `trend-lines`, `diff-waterfall`, `age-histogram`, `package-pareto`. Every function accepts `{:target :plotly | :vega-lite}` and the theme from `vulcan.viz.theme` (one sequential and one categorical palette, severity colours fixed and colour-blind-safe; checked with the dataviz palette validator).

### 9.2 Interactive vs static — the key rendering constraint

HTML and reveal.js can embed interactive Plotly/Vega-Lite; **pptx and PDF cannot** — Quarto drops raw HTML there. Therefore every chart function must be renderable to a static image, and the notebook conventions (§10) select the representation by output profile:

```clojure
(defn chart [ctx spec-fn & args]
  (case (:profile ctx)
    (:html :revealjs) (kind/plotly (apply spec-fn (assoc ctx :target :plotly) args))
    (:pptx :pdf)      (kind/image (static/render-svg (apply spec-fn (assoc ctx :target :vega-lite) args)))))
```

`vulcan.viz.static/render-svg` writes the Vega-Lite spec to a temp file and invokes the pinned `vl-convert vl2svg` / `vl2png` binary via `babashka.process`; the binary's path, version and SHA-256 live in `vulcan.edn` and are checked by `bb check`. The function is a protocol boundary so an in-JVM renderer can replace it later without touching chart code. Tables become `kind/table` (HTML) or a Markdown table (pptx/PDF); long tables are truncated to `:top-n` with a footnote.

---

## 10. Notebooks and presentations

This is the feature the user story in the brief calls "multiple notebooks, same data, converted to presentations". The mechanism is: one report context, one notebook namespace per story, one Clay profile per output format, and a set of writing conventions that make a namespace read correctly both as a document and as a slide deck.

### 10.1 Conventions

1. A notebook namespace starts with a Kindly metadata map and obtains its context from one function, never by querying:

   ```clojure
   (ns notebooks.management.posture
     (:require [vulcan.report.context :as ctx]
               [vulcan.report.kinds :as k]
               [scicloj.kindly.v4.kind :as kind]))

   (def ctx (ctx/load!))   ; reads VULCAN_DB / VULCAN_SCOPE / VULCAN_PROFILE env or clay.edn
   ```

2. Headings come from `kind/md` strings. In reveal.js and pptx, `##` = new slide, `#` = section; Quarto's `slide-level` is fixed at 2 for all profiles so the same headings work everywhere.
3. Code is hidden by default in report profiles (`{:kindly/hide-code true}` at namespace level); the exploration profile shows it.
4. Prose that differs by audience is a function of the profile: `(k/when-profile ctx #{:pptx :revealjs} (kind/md "…"))`. Use sparingly; if a notebook needs many of these it should be two notebooks.
5. Every notebook ends with `(k/appendix ctx)`, which emits the data-provenance slide/section (scan IDs, DB hash, cache age, thresholds, weights). Auditors need it; engineers ignore it.
6. Numbers in prose are never typed; they are interpolated from `(:summary ctx)` so that text and charts cannot disagree.

### 10.2 Templates

`notebooks/_template_report.clj` and `notebooks/_template_slides.clj` are copied, not required. They contain the skeleton above plus commented guidance. `bb new-notebook management/q3-review --kind slides` copies and renames.

### 10.3 Clay configuration and profiles

`clay.edn` holds shared defaults; profiles are maps merged on top by `bb render`:

```clojure
{:base-target-path "target/reports"
 :quarto {:slide-level 2 :toc false}
 :profiles
 {:html     {:format [:quarto :html]
             :quarto {:format {:html {:theme :cosmo :toc true :embed-resources true}}}}
  :revealjs {:format [:quarto :revealjs]
             :quarto {:format {:revealjs {:theme :simple :incremental false
                                          :embed-resources true}}}}
  :pptx     {:format [:quarto :pptx]
             :quarto {:format {:pptx {:reference-doc "resources/quarto/reference.pptx"}}}}
  :pdf      {:format [:quarto :pdf]
             :quarto {:format {:pdf {:documentclass :article}}}}}}
```

Clay's `make!` is called once per notebook per profile: `(clay/make! (merge base profile {:source-path "notebooks/management/posture.clj"}))`. Whether Clay's current release accepts `[:quarto :pptx]`/`[:quarto :pdf]` as first-class formats, or whether the qmd must be post-processed and `quarto render --to pptx` invoked directly, is an open item (§13); the design keeps that behind `vulcan.report.render/render!` so notebooks are unaffected either way.

### 10.4 Rendering commands

```
bb render management/posture --profile revealjs
bb render management/posture --profile pptx
bb render --all --profile html            # every notebook, one HTML report site (Clay :book)
bb report q3 --notebooks management/posture engineering/fix_first --profiles html pptx
```

Outputs land in `target/reports/<profile>/<notebook>.<ext>` and are never committed. The HTML site uses Clay's book mode so that engineering and management notebooks share one index.

### 10.5 Supply-chain constraints at render time

Quarto is invoked from a pinned path with a version check and a checksum verification in `bb check`; `embed-resources true` in the HTML profiles ensures no CDN fetch at view time; reveal.js assets come from Quarto's bundle. Rendering with the network disabled is part of CI (`bb render --all` under `unshare -n` or equivalent).

---

## 11. CLI, build and operations

`bb.edn` tasks: `check`, `migrate`, `ingest`, `enrich`, `decisions`, `summary`, `render`, `report`, `test`, `new-notebook`, `fixtures`. Most tasks delegate to `clojure -M:cli -m vulcan.cli <task>` so that the same code path is available from the REPL as `(vulcan.cli/-main "ingest" ...)`.

Note: `test`, `new-notebook`, and `fixtures` are bb.edn-native tasks that do not delegate through the CLI, as they require Babashka-specific functionality (Kaocha invocation, file copying, fixture regeneration).

Configuration precedence: CLI flags > env (`VULCAN_DB`, `VULCAN_PROFILE`, `CIRCL_API_*`) > `vulcan.edn` in the working directory > defaults. The DuckDB file path defaults to `data/vulcan.duckdb`.

Logging via `clojure.tools.logging` to stderr; ingest and enrich print a one-line summary to stdout suitable for CI logs.

---

## 12. Testing and quality

Fixtures: at least one Trivy report each for a container image with OS + language packages, a filesystem scan, an SBOM scan, an empty result, and a `--list-all-pkgs` report over 16 MiB (to exercise the DuckDB `read_json` path). Fixtures are anonymised copies of real scans.

Ingest tests: `report->rows` round-trip against golden EDN; idempotency (ingest twice → identical table counts); rejection of schema version 1; hash stability across platforms (line endings).

Analysis tests: property tests on the score (§8.3); categorisation table-driven; diff on a hand-made pair of scans.

Viz tests: every chart function renders to both targets on the fixture context without exception; static SVG is non-empty and under a size budget.

Notebook tests: `bb render --all --profile html` and `--profile pptx` in CI, then assert the outputs exist and the pptx contains the expected number of slides (unzip and count `ppt/slides/slide*.xml`).

Architecture test: namespace dependency direction from §2.

---

## 13. Roadmap and open questions

**M1 — Store and ingest (2 weeks).** Schema 0001, migrations, `ingest` task, fixtures, idempotency tests. Exit: a directory of real reports loads in one command and `v_latest_scan_per_artifact` returns sensible rows.

**M2 — Context and analysis (2 weeks).** Report context, categorisation, score, diff, trend, with tests. Exit: `(ctx/build …)` at the REPL answers "top 20 fixes by package" in one expression.

**M3 — Viz and notebooks (2 weeks).** Chart toolkit, static rendering, the two templates, `engineering/fix_first` and `management/posture`, HTML + reveal.js profiles. Exit: same notebook renders as report and as slides.

**M4 — Enrichment and decisions (1–2 weeks).** CIRCL provider, EPSS bulk provider, cache freshness, OpenVEX import/export.

**M5 — pptx/PDF and hardening (1–2 weeks).** Corporate `reference.pptx`, static image path validated, offline CI render, docs.

Open questions to resolve before M3 (each becomes an ADR):

1. Does Clay 2.0.21 drive `pptx`/`pdf` directly through `:format`, or is a `quarto render` post-step needed? (Check against the Clay docs and a spike.)
2. Which exact Vega-Lite schema version does tableplot 1-beta17 emit, and which `vl-convert` release to pin for it? (Spike: render every chart in §9.1 to SVG from the fixture context.)
3. Should packages from `--list-all-pkgs` get their own `package` table in v1 (needed for "% of packages affected"), or is it deferred to M4? Recommendation: include in 0001 as it is cheap at ingest and painful to backfill.
4. Score weights: are they per-audience (engineering vs management) or single? Recommendation: single, printed in the appendix; per-audience weights invite "the number changed" conversations.

---

## 14. References (checked 28 Aug 2026)

- Trivy reporting formats and JSON structure: https://trivy.dev/docs/latest/configuration/reporting/
- Trivy JSON schema v2 documentation discussion: https://github.com/aquasecurity/trivy/discussions/7552
- Trivy filtering, status values, `--ignore-unfixed`, `.trivyignore`, Rego: https://trivy.dev/docs/latest/configuration/filtering/
- Trivy vulnerability scanner, severity selection: https://trivy.dev/docs/latest/guide/scanner/vulnerability/
- Trivy VEX support (experimental): https://trivy.dev/docs/latest/guide/supply-chain/vex/
- DuckDB JDBC driver `org.duckdb:duckdb_jdbc` 1.5.5.1: https://central.sonatype.com/artifact/org.duckdb/duckdb_jdbc ; https://github.com/duckdb/duckdb-java
- DuckDB `read_json` parameters: https://duckdb.org/docs/current/data/json/loading_json.html
- next.jdbc: https://github.com/seancorfield/next-jdbc/blob/develop/doc/getting-started.md
- tech.ml.dataset.sql (`result-set->dataset`): https://github.com/techascent/tech.ml.dataset.sql
- Clay 2.0.21 and documentation: https://clojars.org/org.scicloj/clay ; https://scicloj.github.io/clay/
- tablecloth 8.024: https://clojars.org/scicloj/tablecloth
- tableplot 1-beta17: https://clojars.org/org.scicloj/tableplot
- Quarto reveal.js: https://quarto.org/docs/presentations/revealjs/
- Quarto PowerPoint (`reference-doc`, slide-level, limitations): https://quarto.org/docs/presentations/powerpoint.html
- CIRCL Vulnerability-Lookup API: https://www.vulnerability-lookup.org/documentation/api/
- vl-convert (standalone CLI, offline, no Node/browser): https://github.com/vega/vl-convert
- darkstar (evaluated, rejected — Vega-Lite 4.10.1): https://github.com/applied-science/darkstar
