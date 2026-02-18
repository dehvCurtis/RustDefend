# RustDefend Web Dashboard

A static HTML/CSS/JS dashboard for viewing RustDefend scan results.

## Usage

1. Run a scan with JSON output:

```bash
rustdefend scan /path/to/project --format json > report.json
```

2. Open `index.html` in your browser

3. Click "Load JSON Report" and select your `report.json` file

## Features

- Sortable table (click column headers)
- Filter by severity, chain, or free-text search
- Expandable detail rows with snippet and recommendation
- Dark theme
- No external dependencies — pure HTML/CSS/JS
