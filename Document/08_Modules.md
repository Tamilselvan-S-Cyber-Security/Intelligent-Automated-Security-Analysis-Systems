# Module Description

## 8.1 Entry Points

- **Flask:** `main.py` imports `app` from `app.py` and runs the server.
- **Streamlit:** `wolf.py` is the dashboard application.

## 8.2 Flask Application (`app.py`)

### Responsibilities

- Handles routes:
  - `/` index page
  - `/scan` scan form + results (basic/api scan types)
- Manages sessions and cookie security settings.
- Provides file-based API key management (`api_keys.json`).

### Key Classes/Functions

- `ApiKeyManager`
  - `generate_key(name)`
  - `validate_key(key)`
  - `revoke_key(key)`

### Core Data Flow

- User submits URL + scan_type
- URL validated (via `utils.validator.validate_url`)
- `VulnerabilityScanner` runs enabled checks
- Results are passed to `utils.reporter.generate_report` for final output

## 8.3 Scanner Coordinator (`modules/scanner.py`)

### Responsibilities

- Central orchestration of scanning modules.
- Runs scans concurrently using `ThreadPoolExecutor`.
- Aggregates results into a single dictionary:
  - `xss`, `sqli`, `ports`, `paths`, `misconfig`, `xxe`, `ssrf`, `rce`, `idor`, `csrf`, `jwt`, `api`, `bruteforce`, `ssl`, and `summary`.

### Risk Summary

- Computes `risk_level` based on total vulnerability counts.

## 8.4 Vulnerability Modules (`modules/*_scanner.py`)

The repository contains multiple scanners. Each typically provides:

- An initialization with `timeout` and `verbose` parameters.
- A `scan(target, api_key=None)` function that returns a list of findings.

Examples:

- `modules/xss_scanner.py`: identifies reflected or stored XSS patterns.
- `modules/sqli_scanner.py`: tests for SQL injection patterns.
- `modules/ssl_scanner.py`: checks TLS configuration and certificate indicators.
- `modules/api_scanner.py`: tests API endpoints patterns and security checks.

## 8.5 Network & OSINT (`modules/network_scanner.py`)

### Responsibilities

- DNS resolution, record enumeration, reverse DNS
- Ping and traceroute
- WHOIS lookup
- Additional network analysis utilities

### Note

Some functions rely on system commands (`ping`, `tracert`) and require OS permissions.

## 8.6 Web Scraper (`web_scraper.py`)

### Responsibilities

- Extract clean website text using `trafilatura`
- Extract internal links to map attack surface
- Identify potential input fields/forms from HTML
- Crawl website pages (depth/page limits)

## 8.7 AI Layer (`wolf_api.py`, `security_analyzer.py`)

### `WolfAPI`

- Wraps Gemini / demo responses.
- Provides structured output (JSON-like with summary, score, vulnerabilities, recommendations).

### `security_analyzer.py`

- Builds prompts for:
  - website analysis
  - threat detection (code/text)
  - simulated web application scan

## 8.8 Reporting (`report_generator.py`)

### Responsibilities

- Converts scanning output into HTML report using Jinja templates.
- Produces charts:
  - security score gauge (Plotly)
  - issue distribution pie (Plotly)
  - category counts (Plotly)
  - header heatmap (Matplotlib/Seaborn)

### Output

- Primary output: HTML string (rendered report)

## 8.9 Utilities (`utils/`)

- `utils/validator.py`: URL validation.
- `utils/reporter.py`: report formatting and saving.
- `utils/encoding_utils.py`: encoding handling.
- `utils/safe_unpack.py`: safer unpacking patterns.
