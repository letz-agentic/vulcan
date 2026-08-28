# 0007 — VEX statements must address products by OCI PURL

Status: accepted · 28 Aug 2026 · Implements spec §7.3

## The goal

§7.3 wants exported decisions to be usable as `trivy --vex <file>`, "so
scanner output and reports agree". Producing a syntactically valid OpenVEX
document is not enough for that; the scanner has to *act* on it.

## What went wrong first

The obvious implementation puts the decision's scope — a package PURL — into
the statement's `products`. Trivy accepted the file without complaint and
suppressed **nothing**. "Accepted" and "applied" are different tests, and only
the second one matters.

Measured against Trivy 0.74, `alpine:3.19`, `CVE-2026-40200` / `musl`:

| statement shape | suppressed |
|---|---|
| `products: [package purl]` | none |
| `subcomponents: [package purl]`, no `products` | none |
| `subcomponents: […]`, `products: [{"@id": "alpine:3.19"}]` | none |
| `subcomponents: […]`, `products: [{"@id": "*"}]` | none |
| `subcomponents: [package purl]`, `products: [image OCI purl]` | **musl, musl-utils** |

Trivy matches `products` against the artifact's full OCI PURL and
`subcomponents` against packages. Nothing else works — not the tag, not a
wildcard, not omission.

## Decision

`vulcan.enrich.vex` addresses products the way the scanner does:

- a **package-scoped** decision exports as a `subcomponent`, with `products`
  naming every image in the store that actually contains that package — which
  only the store knows, from the `package` table;
- an **artifact-scoped** decision names that artifact's OCI PURL;
- `*` names every artifact individually.

`oci-purl` implements Docker's reference normalisation, which is implicit
everywhere and written down almost nowhere: a first segment containing a dot
or colon (or `localhost`) is a registry host, otherwise the reference is
Docker Hub, and a single-segment name lives under an implicit `library/`.

On import, `subcomponents` take precedence over `products` when both are
present, so scope survives an export/import/export round trip.

## Verified

`bb decisions export` → `trivy --vex` suppresses `CVE-2026-40200` for both
`musl` and `musl-utils` on `alpine:3.19`, and leaves the other eight findings
untouched.

## Consequences

Export now reads the store, not just the `decision` table. That is the right
dependency: a VEX statement has to name the product it is about, and a
decision row deliberately carries one scope rather than a product/subcomponent
pair.
