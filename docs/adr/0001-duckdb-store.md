# 0001 — DuckDB as the canonical store

Status: accepted · 28 Aug 2026 · Spec §3, §5

## Decision

One DuckDB file (`org.duckdb/duckdb_jdbc` 1.5.5.1) reached through `next.jdbc`,
with HoneySQL for composed queries and raw SQL for the DDL.

## Considered

- **SQLite** — ubiquitous, but row-oriented: the analytic aggregations this
  project exists to run (group-by across hundreds of thousands of findings)
  are exactly what it is worst at, and its JSON support is bolted on.
- **Datalevin** — elegant for the CVE graph, but adds a second query language
  for no v1 benefit.
- **Parquet + tablecloth, no database** — no place to put append-only
  provenance, and no views to act as the store/analysis contract.

## Consequences

Columnar analytics, native JSON and Parquet, a single file, zero operations.
The cost is that DuckDB's storage format has changed across major versions, so
`vulcan.store.migrate` records the engine version with every migration and
refuses to open a file written by a newer driver.

## Verified

DuckDB 1.5.5 via JDBC 1.5.5.1; all three views (`v_finding_enriched`,
`v_latest_scan_per_artifact`, `v_scan_summary`) query correctly, including
DuckDB's `FILTER (cond)` shorthand and `* EXCLUDE (..)`.
