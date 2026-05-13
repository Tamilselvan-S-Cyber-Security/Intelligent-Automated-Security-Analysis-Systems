# PDF Export (Recommended Workflow)

This project’s documentation is authored in Markdown under `Document/`. To export to PDF, use one of the following methods.

## Diagram Note (SVG Flowcharts)

This report includes SVG flowcharts under `Document/assets/flowcharts/`. Most Markdown-to-PDF exporters support SVG, but if your exported PDF shows blank diagrams, use one of these workarounds:

- Export from a browser-based Markdown preview that supports SVG and then **Print -> Save as PDF**.
- Convert SVG to PNG (optional) and update the Markdown image links.

## Option A (Recommended): VS Code "Markdown PDF" Extension

1. Install extension: **Markdown PDF** (publisher: yzane).
2. Open `Document/REPORT.md`.
3. Use Command Palette:

- `Markdown PDF: Export (pdf)`

This produces a PDF for the current Markdown file.

## Option B: Pandoc (if installed)

If `pandoc` is installed on your machine, you can generate a single PDF by converting the merged report.

1. Export each file or merge them into a single `REPORT_FULL.md`.
2. Run (example):

```bash
pandoc REPORT_FULL.md -o REPORT.pdf
```

## Note

Mermaid diagrams in Markdown may need a renderer (extension/preview) before converting to PDF. If your exporter does not support Mermaid, keep diagrams as images or include the Mermaid code blocks as-is.
