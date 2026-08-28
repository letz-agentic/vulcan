# 0005 — `resolved` splits three ways, not two

Status: accepted · 28 Aug 2026 · Refines spec §8.4

## Context

The spec says a resolved finding is either `fixed-by-upgrade` (installed
version changed) or `disappeared` (package gone).

## Two problems with the binary split

**It is not decidable from findings alone.** The obvious implementation asks
"is this package still in the current findings?" — but a package upgraded past
its *last* CVE has no findings left. It would be labelled `disappeared` when it
is in fact right there, fixed. That is the most common good outcome in the
corpus, reported as the one thing it is not.

`vulcan.analysis.diff` therefore reads the **`package` table**, not the
findings, to decide whether a package is still installed.

**The two labels do not cover the cases.** With the inventory in hand, three
distinct things can have happened:

| current inventory              | label                |
|--------------------------------|----------------------|
| package present, newer version | `fixed-by-upgrade`   |
| package absent                 | `disappeared`        |
| package present, same version  | `no-longer-reported` |

The third is real: the advisory stopped applying — withdrawn, re-scored, or
re-scoped — without anything about the image changing. Folding it into
`disappeared` would tell a reader the package was removed when it was not.

## Decision

Report all three. When scans were run without `--list-all-pkgs` there is no
inventory and the outcomes genuinely cannot be distinguished; the single label
`resolved` is used, rather than guessing.

## Consequences

One more value for consumers of the diff to handle. `vulcan.viz.theme`
colours it neutral grey — it is neither progress nor regression.
