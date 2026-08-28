# 0004 — vl-convert 1.9.0, compiling against Vega-Lite 5.21

Status: accepted · 28 Aug 2026 · Resolves spec §13 open question 2

## Question

Which Vega-Lite schema version does tableplot 1-beta17 emit, and which
`vl-convert` release should be pinned for it?

## Answer

tableplot's Hanami target emits specs with **no `$schema` field**, so the
version is chosen by the converter rather than declared by the spec.

`vl-convert` 1.9.0 supports Vega-Lite 5.8, 5.14–5.17, 5.19–5.21 and 6.1, with
5.21 as its default. Rendering tableplot's output at 5.21 produces correct SVG
(verified: a `layer-bar` spec rendered to a well-formed 7.7 KB SVG).

Pinned in `vulcan.edn`:

```clojure
:vl-convert {:path       "tools/bin/vl-convert"
             :version    "1.9.0"
             :vl-version "5.21"
             :sha256     "9a12ff18af9abf895a5bdf22c74a5b602bcbab0714ee1a290f5f6305a6cefc74"}
```

`vulcan.viz.charts` writes an explicit `$schema` of v5 into every spec it
builds, so our own charts do not depend on the converter's default; the
`:vl-version` flag pins the compiler for anything that omits it.

## Why not darkstar

`applied-science/darkstar` would have been cleaner — a pure JVM dependency,
no external binary — but it bundles Vega-Lite 4.10.1, two major versions
behind what tableplot emits. Rejected, as the spec anticipated.

## Consequences

An external binary in a project whose supply-chain rule is "everything
pinned". Mitigated by pinning path, version *and* SHA-256, and by `bb check`
verifying all three before any render that needs it. `vulcan.viz.static`
defines a `StaticRenderer` protocol so an in-JVM implementation can replace it
without touching chart code.
