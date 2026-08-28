# 0003 — Clay drives all four output formats; profiles must own their front matter

Status: accepted · 28 Aug 2026 · Resolves spec §13 open question 1

## Question

Does Clay 2.0.21 drive `pptx`/`pdf` directly through `:format`, or is a
`quarto render --to` post-step needed?

## Answer, from a spike

Clay drives all four directly. No post-step is needed. **But** the format
vector alone is not enough.

Clay writes its `:quarto {:format {...}}` config *verbatim* into the qmd front
matter, and `clay-default.edn` ships a map containing `html` and `revealjs`.
A spec of `{:format [:quarto :pptx]}` that leaves `:quarto` alone therefore
emits front matter offering `html` and `revealjs`, and Quarto renders **HTML
while reporting success** — a silent wrong-format render.

Each profile in `vulcan.report.render/profiles` therefore carries its own
complete `:quarto :format` map. With that, the spike produced:

| profile  | output                        |
|----------|-------------------------------|
| html     | `tiny.html` (self-contained)  |
| revealjs | `tiny-revealjs.html`          |
| pptx     | `tiny.pptx`                   |
| pdf      | `tiny.pdf`                    |

## The second trap: `kind/image` is invisible in pptx

Clay renders `kind/image` inside a `::: {.clay-image}` fenced div. Pandoc's
pptx writer discards content in a Div it does not recognise. The first working
pptx had nine correctly titled slides and **zero images** — no error anywhere.

`vulcan.report.kinds/static-chart` therefore writes the PNG itself and emits a
bare `![](vulcan-charts/chart-001.png)`, which Pandoc turns into a real
picture. The images live beside the generated qmd, because Quarto resolves
relative paths from the qmd's directory.

## Third: Quarto cannot put an interactive Plotly figure in a PDF

The pdf spike failed with `ModuleNotFoundError: No module named 'plotly'`.
This is the constraint §9.2 predicts, and the reason every chart function must
offer a Vega-Lite form. With the static path in place, pdf renders.

## Consequences

- `:hide-code true` sits in `base-defaults`; the `:explore` profile turns it
  back on (spec §10.1 rule 3).
- `slide-level: 2` is set on every profile, so `##` is a slide everywhere.
- Nothing above `render!` knows any of this.
