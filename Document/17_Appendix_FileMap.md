# Appendix A: File/Folder Map

## A.1 Top-Level Structure (Key Items)

| Path | Purpose |
|---|---|
| `main.py` | Flask entry point (runs server) |
| `app.py` | Flask app, routes, API key manager, scan integration |
| `wolf.py` | Streamlit dashboard UI entry point |
| `modules/` | Modular scanners and core engine components |
| `utils/` | Helpers: validation, reporting, encoding fixes, safe unpack |
| `templates/` | HTML templates (Flask UI + report template) |
| `static/` | Static assets (css/js) |
| `reports/` | Output folder for generated reports (runtime) |
| `requirements.txt` | Python dependencies |
| `workflow_map.md` | Mermaid flow diagrams |

## A.2 Modules Folder (Summary)

| Module | Description |
|---|---|
| `modules/scanner.py` | Scan orchestrator (`VulnerabilityScanner`) |
| `modules/xss_scanner.py` | XSS checks |
| `modules/sqli_scanner.py` | SQLi checks |
| `modules/port_scanner.py` | Port scanning |
| `modules/path_scanner.py` | Path discovery |
| `modules/misconfig_scanner.py` | Misconfiguration checks |
| `modules/ssl_scanner.py` | TLS/SSL checks |
| `modules/api_scanner.py` | API security checks |
| `modules/bruteforce_scanner.py` | Weak credential/bruteforce heuristics |
| `modules/network_scanner.py` | DNS/Network scanner |
| `modules/subdomain_finder.py` | Subdomain enumeration helpers |

## A.3 Utilities Folder

| Utility | Description |
|---|---|
| `utils/validator.py` | URL validation |
| `utils/reporter.py` | Report formatting/saving |
| `utils/report_generator.py` | Additional report generator implementation |
| `utils/encoding_utils.py` | Encoding/decoding helpers |
| `utils/safe_unpack.py` | Safer unpacking utilities |

## A.4 Notes

- Some folders like `venv/` and `__pycache__/` are environment artifacts.
- `back-end/` appears to contain additional backend content and temporary extracted archives.
