# Vulcan V

**Vulnerability categorization, analysis and visualization — in Clojure.**

Trivy JSON in, one DuckDB store, and reports that render as an HTML document,
a reveal.js deck, a PowerPoint file or a PDF from the same numbers.

See [`docs/specs/vulcan-v-dev-spec.md`](docs/specs/vulcan-v-dev-spec.md) for
the design and [`docs/adr/`](docs/adr/) for the decisions that changed once
they met reality.

## Status

Milestones M1–M4 of the spec roadmap are implemented and tested.

| Milestone | Scope | State |
|---|---|---|
| M1 | Store, migrations, Trivy ingest, fixtures, idempotency | done |
| M2 | Report context, categorisation, fix-first score, diff, trend | done |
| M3 | Chart toolkit, static rendering, notebooks, all four profiles | done |
| M4 | KEV/EPSS/CIRCL enrichment, cache freshness, OpenVEX decisions | done |
| M5 | Corporate `reference.pptx`, offline CI render, hardening | **not started** |

All four output profiles (`html`, `revealjs`, `pptx`, `pdf`) render, which is
ahead of the M3 exit criterion — the spec put pptx and PDF in M5. What is *not*
done from M5 is the corporate `reference.pptx` template, the offline CI render
and the hardening pass.

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

# 3. add exploitability data: KEV, EPSS, descriptions
bb enrich --max-age 7d

# 4. see what is there
bb summary

# 5. render
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
| `bb enrich` | refresh KEV/EPSS/CIRCL (`--max-age 7d`, `--offline`, `--status`) |
| `bb decisions` | OpenVEX `import <file>` / `export [file]` / `list` |
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
  enrich/    provider, http, kev, epss, circl, cache, vex
  analysis/  categorize, score, diff, trend, core
  viz/       theme, charts, static (vl-convert)
  report/    context, kinds, render
  cli.clj
notebooks/   engineering/, management/, explore/, _template_*
resources/   sql/ (migrations), fixtures/{trivy,vex}/, logback.xml
docs/        specs/, adr/, notebook-guide.md, schema.md
```

Layer dependencies run one way only, and `vulcan.arch-test` fails the build if
they stop doing so.

## Writing notebooks

See [`docs/notebook-guide.md`](docs/notebook-guide.md). The rule that matters
most: use `k/chart` and `k/table`, never `kind/plotly` directly — an
interactive chart is *silently dropped* from pptx and PDF output.

## Enrichment

`bb enrich` fills the exploitability axis, which is what turns a severity list
into a priority list — an EPSS-`likely` HIGH outranks a theoretical CRITICAL.

Three sources, each the one that owns its signal:

| signal | source | shape |
|---|---|---|
| Known exploited | CISA KEV catalogue | one bulk fetch |
| EPSS score and percentile | FIRST | batched, 100 CVEs per request |
| Description, sighting counts | CIRCL Vulnerability-Lookup | per id, rate-limited |

Only stale entries are fetched: `--max-age 7d` skips anything refreshed inside
the window. The cache *is* the `vulnerability` table, so there is no second
store to keep in sync, and every report's appendix states the cache age.

```bash
bb enrich --max-age 7d          # refresh what is stale
bb enrich --status              # coverage and age, fetch nothing
bb enrich --offline             # make no requests at all
bb enrich --sightings           # also fetch CIRCL sighting counts (slower)
```

CIRCL rate-limits unauthenticated callers to 20 requests per window, so
descriptions may come back partial on a large store — the run backs off and
says so rather than stalling. Set `CIRCL_API_ORG` / `_USER` / `_KEY` to raise
the limit. KEV and EPSS are bulk and complete regardless, so the
exploitability axis does not depend on CIRCL being reachable.

**Nothing ever fails because an API is down.** Providers degrade to returning
nothing, `--offline` makes no request at all, and reports render from whatever
is cached, stamped with its age.

## Decisions (OpenVEX)

A decision is a human statement about a finding — *not affected, here is why,
expires then*. They live in OpenVEX so the same statements can be handed back
to the scanner:

```bash
bb decisions import security/vex.json
bb decisions list
bb decisions export vex.json
trivy image --vex vex.json registry/app:1.2.3
```

That last line is the point, and it is verified rather than assumed: our
exported document suppresses the findings it covers when Trivy re-scans. See
[ADR 0007](docs/adr/0007-vex-product-addressing.md) for why addressing
products correctly turned out to be the hard part.

Expiry is honoured at analysis time, so a time-boxed exception stops applying
on its own.

## Configuration

CLI flags > environment (`VULCAN_DB`, `VULCAN_SCOPE`, `VULCAN_PROFILE`,
`CIRCL_API_ORG` / `_USER` / `_KEY`) > `vulcan.edn` > defaults. The store
defaults to `data/vulcan.duckdb`.

## Tests

```bash
bb test
```

143 tests, 557 assertions. Property tests cover the score (monotonicity in
every input; a KEV CRITICAL fixable finding outranks anything without KEV).
Ingestion idempotency, the layering rule, chart rendering to both targets, the
colour ramp's greyscale legibility, and the OpenVEX round trip are all
enforced rather than assumed.

**No test touches the network.** Enrichment providers are mocked through the
one-method `Enricher` protocol, and the parsers are tested against captured
payloads — a suite whose result depends on a public API being up is not a
suite.
