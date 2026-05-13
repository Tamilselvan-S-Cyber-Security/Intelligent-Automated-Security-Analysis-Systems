# Requirements Specification

## 6.1 Software Requirements

- Python 3.x
- Dependencies (from `requirements.txt`):
  - Flask, Flask-RESTful
  - requests, urllib3
  - beautifulsoup4
  - streamlit
  - cryptography
  - plotly, pandas
  - jinja2
  - Pillow
  - matplotlib, seaborn
  - aiohttp
  - chardet
  - networkx
  - dnspython, python-whois

## 6.2 Hardware Requirements

- Minimum 4 GB RAM (recommended 8 GB)
- Dual-core CPU or better
- Stable internet connection for online analysis (AI mode)

## 6.3 Functional Requirements

| FR No. | Requirement | Description |
|---|---|---|
| FR1 | URL validation | Validate target URL before scanning |
| FR2 | Modular scanning | Run selected vulnerability checks |
| FR3 | Concurrency | Execute scans in parallel for performance |
| FR4 | Result aggregation | Summarize counts, severity, and risk |
| FR5 | Dashboard UI | Provide interactive UI for scanning and report download |
| FR6 | AI-assisted analysis | Provide structured summary and recommendations |
| FR7 | Report generation | Export HTML report with charts |
| FR8 | Network scanning | DNS lookup, ping, traceroute, WHOIS, reverse DNS |

## 6.4 Non-Functional Requirements

| NFR No. | Requirement | Description |
|---|---|---|
| NFR1 | Usability | Simple inputs, guided flow |
| NFR2 | Reliability | Graceful handling of timeouts/errors |
| NFR3 | Maintainability | Modular code organization |
| NFR4 | Extensibility | Add new scanners without large refactors |
| NFR5 | Security | Avoid hardcoding API keys; use env vars |

## 6.5 Constraints

- Some advanced checks require realistic crawling and authenticated sessions.
- AI analysis depends on external API availability and keys.
- Legal/ethical usage constraints: scanning should be performed only on authorized targets.
