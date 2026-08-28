# 0002 — ResultSet → dataset goes through next.jdbc, not tech.ml.dataset.sql

Status: accepted · 28 Aug 2026 · Spec §3 (supersedes the row in that table)

## Context

The spec nominated `tech.v3.dataset.sql/result-set->dataset` for the
ResultSet→dataset hop, using it *only* for that hop because its connection
helpers are PostgreSQL-oriented.

## Problem

It does not work against the driver the spec also chose. `result-set->dataset`
calls `ResultSet.getRow` to track cursor position; `org.duckdb.DuckDBResultSet`
throws `SQLFeatureNotSupportedException` for that method:

```
Execution error (SQLFeatureNotSupportedException)
  at org.duckdb.DuckDBResultSet/getRow (DuckDBResultSet.java:673)
```

The two library choices in §3 are individually reasonable and jointly
unworkable.

## Decision

`vulcan.store.query/->dataset` materialises rows through `next.jdbc/execute!`
— the driver-blessed path — and builds the dataset with `tc/dataset`.

## Consequences

One intermediate row map per result row. Acceptable at this scale: a scope is
thousands to low millions of findings and DuckDB has already done the
aggregation before the rows cross the JDBC boundary.

If it ever stops being acceptable, the honest fix is DuckDB's Arrow export,
not reinstating a driver-incompatible helper. The conversion is behind one
private function, so that change touches one place.

Two read-path details had to be fixed at the same seam:

- **Column naming.** camel-snake-kebab's `->kebab-case` splits on digit
  boundaries, turning `cvss_v3_score` into `:cvss-v-3-score`. Our column names
  are snake_case by construction, so `vulcan.store.db/snake->kebab` swaps the
  separator and nothing else — lossless, and reversible.
- **Array columns.** DuckDB returns `VARCHAR[]` as `java.sql.Array`. A
  `ReadableColumn` extension reads them as vectors, so no layer above the
  store ever handles a JDBC array.
