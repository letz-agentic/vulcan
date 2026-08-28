# Vulcan V

**Vulnerability categorization, analysis and visualization — in Clojure.**

Trivy JSON in, one DuckDB store, and reports that render as an HTML document,
a reveal.js deck, a PowerPoint file or a PDF from the same numbers.

See [`docs/specs/vulcan-v-dev-spec.md`](docs/specs/vulcan-v-dev-spec.md) for
the design and [`docs/adr/`](docs/adr/) for the decisions that changed once
they met reality.

## Status

Milestones M1–M3 of the spec roadmap are implemented and tested.

| Milestone | Scope | State |
|---|---|---|
| M1 | Store, migrations, Trivy ingest, fixtures, idempotency | done |
| M2 | Report context, categorisation, fix-first score, diff, trend | done |
| M3 | Chart toolkit, static rendering, notebooks, all four profiles | done |
| M4 | CIRCL/EPSS enrichment, OpenVEX decisions | **not started** |
| M5 | Corporate `reference.pptx`, offline CI render, hardening | **not started** |

All four output profiles (`html`, `revealjs`, `pptx`, `pdf`) render, which is
ahead of the M3 exit criterion — the spec put pptx and PDF in M5. What is *not*
done from M5 is the corporate `reference.pptx` template, the offline CI render
and the hardening pass.

The `vulnerability` and `decision` tables exist and every layer reads them, so
enrichment lands without a schema change. Until M4 they are empty, which means
every finding currently categorises as `unlikely` on the exploitability axis —
the appendix of every report says so explicitly rather than letting a reader
assume otherwise.

## Requirements

- JDK 21+ (developed against 26)
- [Clojure CLI](https://clojure.org/guides/install_clojure)
- [Babashka](https://babashka.org/)
- Trivy, to produce reports

## Pinned tools

Quarto and `vl-convert` are pinned into `tools/`, not taken from the machine:
a render has to be reproducible from a clean checkout (spec §10.5). They are
git-ignored; install them with:

```bash
mkdir -p tools && cd tools
curl -sL -o q.tar.gz https://github.com/quarto-dev/quarto-cli/releases/download/v1.10.18/quarto-1.10.18-macos.tar.gz
curl -sL -o v.zip    https://github.com/vega/vl-convert/releases/download/v1.9.0/vl-convert_osx-arm64.zip
tar xzf q.tar.gz && unzip -oq v.zip && rm q.tar.gz v.zip && chmod +x bin/quarto bin/vl-convert
```

Then verify — this checks the version of both and the SHA-256 of `vl-convert`
against the pins in `vulcan.edn`:

```bash
bb check
```

On Linux, substitute `quarto-1.10.18-linux-amd64.tar.gz` and
`vl-convert_linux-64.zip`, and update the `:sha256` in `vulcan.edn` to that
binary's checksum.

The `pdf` profile additionally needs a LaTeX engine. It is a separate,
user-level install (no sudo, ~200 MB) and only that one profile needs it:

```bash
tools/bin/quarto install tinytex
```

`bb render ... --profile pdf` checks for it first and tells you this if it is
missing, rather than failing inside Quarto several minutes in.

`bb` puts `tools/bin` on `PATH` for every task, because Clay shells out to a
bare `quarto`.

## Quick start

```bash
# 1. produce a scan. --list-all-pkgs matters: without it, "fraction of
#    packages affected" cannot be computed later, at all.
trivy image --format json --list-all-pkgs --scanners vuln \
  --output reports/$(date -u +%Y%m%dT%H%M%SZ)_app.json registry/app:1.2.3

# 2. load it
bb ingest reports/

# 3. see what is there
bb summary

# 4. render
bb render management/posture  --profile html
bb render engineering/fix_first --profile pptx
```

Outputs land in `target/reports/` and are never committed.

To try it without a scanner, the fixtures are real reports of public images:

```bash
bb ingest resources/fixtures/trivy
```

## Tasks

| task | what |
|---|---|
| `bb check` | verify the pinned tools |
| `bb migrate` | create or upgrade the store |
| `bb ingest <path>` | ingest a file or directory (`--dry-run` to validate only) |
| `bb summary` | print the KPI map for the current scope |
| `bb render <nb> --profile <p>` | render one notebook |
| `bb report --profiles html,pptx` | render notebooks across profiles |
| `bb test` | run the suite |
| `bb fixtures` | regenerate fixtures from `data/raw/` |
| `bb new-notebook <group/name> [--kind slides]` | copy a template |

Profiles: `html`, `revealjs`, `pptx`, `pdf`, `explore`.

Every task delegates to `vulcan.cli`, so the same code path is available at the
REPL as `(vulcan.cli/-main "ingest" "reports/")`.

## At the REPL

```clojure
(require '[vulcan.report.context :as ctx] '[tablecloth.api :as tc])

(def c (ctx/load!))

(:summary c)

;; top 20 fixes by package, in one expression
(-> c :by-package (tc/head 20))
```

`scope` is `:latest` (one scan per artifact — current posture),
`{:artifacts [..]}`, `{:scan-ids [..]}` or `{:since inst}`.

## Layout

```
src/vulcan/
  ingest/    json, schema (Malli), trivy (pure normalisation), dir (driver)
  store/     db, migrate, write, query          <- the only SQL
  analysis/  categorize, score, diff, trend, core
  viz/       theme, charts, static (vl-convert)
  report/    context, kinds, render
  cli.clj
notebooks/   engineering/, management/, explore/, _template_*
resources/   sql/ (migrations), fixtures/trivy/, logback.xml
docs/        specs/, adr/, notebook-guide.md, schema.md
```

Layer dependencies run one way only, and `vulcan.arch-test` fails the build if
they stop doing so.

## Writing notebooks

See [`docs/notebook-guide.md`](docs/notebook-guide.md). The rule that matters
most: use `k/chart` and `k/table`, never `kind/plotly` directly — an
interactive chart is *silently dropped* from pptx and PDF output.

## Configuration

CLI flags > environment (`VULCAN_DB`, `VULCAN_SCOPE`, `VULCAN_PROFILE`) >
`vulcan.edn` > defaults. The store defaults to `data/vulcan.duckdb`.

## Tests

```bash
bb test
```

102 tests. Property tests cover the score (monotonicity in every input; a KEV
CRITICAL fixable finding outranks anything without KEV). Ingestion
idempotency, the layering rule, chart rendering to both targets, and the
colour ramp's greyscale legibility are all enforced rather than assumed.
