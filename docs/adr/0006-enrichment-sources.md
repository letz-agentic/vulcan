# 0006 — Enrichment sources: bulk KEV and EPSS, CIRCL for description only

Status: accepted · 28 Aug 2026 · Refines spec §7.1

## Context

The spec named CIRCL Vulnerability-Lookup for all four enrichment signals:
`/api/vulnerability/{id}`, `/api/cisa_kev/`, `/api/sighting/?vuln_id=…` and
`POST /api/exploit-hazard/batch`.

## What the endpoints actually do

Probed on 28 Aug 2026:

| endpoint | result |
|---|---|
| `GET /api/vulnerability/{id}` | 200 — a **CVE JSON 5.0 record**, served verbatim |
| `GET /api/sighting/?vuln_id={id}` | 200 — `{metadata:{count}, data:[…]}` |
| `GET /api/sighting/{id}` | **404** |
| `GET /api/cisa_kev/{id}` | **404** |
| `GET https://api.first.org/data/v1/epss?cve=A,B` | 200 — batches, `epss` + `percentile` |
| CISA KEV feed (`cisa.gov/.../known_exploited_vulnerabilities.json`) | 200 — 1685 entries |

Two corrections to the spec's list: sightings need the **query-parameter**
form, and there is no per-id KEV endpoint on CIRCL.

## Decision

Signals come from the source that owns them, and bulk wins where it exists:

- **KEV** — CISA's own catalogue, fetched whole. One request answers for the
  entire store, it is authoritative rather than a mirror, and it can be primed
  before an offline run.
- **EPSS** — FIRST's API, batched 100 CVEs per request, with the daily bulk
  CSV available as a second provider behind the same protocol.
- **CIRCL** — description and sighting counts, which no bulk feed provides.

The description lives at `containers.cna.descriptions` because CIRCL returns
the upstream CVE 5.0 record rather than a CIRCL-shaped one. The sightings
count is read from `metadata.count`, **not** `(count data)`: a page holds at
most 1000, and CVE-2021-44228 has 1780.

## Rate limiting, and why it needed a circuit breaker

CIRCL allows 20 requests per window unauthenticated and answers a 429 with
`Retry-After: 30` and `x-ratelimit-reset`.

Honouring `Retry-After` per request was correct and catastrophically slow: 53
vulnerabilities × 4 attempts × 30 s at concurrency 2 turned a 60-second run
into a 40-minute one. Being rate-limited is a fact about the *source*, not
about one id, so `vulcan.enrich.provider/breaker` gives up on CIRCL for the
rest of the run the first time a request exhausts its retries. The measured
run went from >600 s (killed) to **66 s**, with EPSS and KEV complete and
descriptions partial — which is exactly the degradation §7.2 asks for.

Set `CIRCL_API_ORG` / `_USER` / `_KEY` to raise the limit.

## Consequences

- The exploitability axis is fully driven by bulk sources, so it is complete
  even when CIRCL is unavailable. Only descriptions degrade.
- `enrich!` writes a row for every requested id, so "how much of the store is
  enriched" is answerable rather than inferred from absence.
- A KEV fetch that *fails* records nothing, rather than `kev = false`
  everywhere — which would be indistinguishable from a confident "none of
  these are exploited".
