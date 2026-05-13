# Problem Statement & Objectives

## 3.1 Problem Statement

Security assessment of web applications and services requires specialized expertise and time. Teams often face constraints:

- Limited manpower for continuous testing
- Inconsistent coverage of common vulnerability categories
- Lack of standard reporting format for stakeholders

A system is required that automates key security checks, correlates results, and produces an actionable report.

## 3.2 Objectives

- Implement an automated vulnerability scanning platform with modular scanning components.
- Support both interactive UI and web endpoints.
- Provide risk scoring and severity prioritization.
- Produce a detailed report with:
  - Summary findings
  - Vulnerability lists
  - Recommendations
  - Visual charts

## 3.3 Functional Objectives (mapped to code)

| Objective | Implementation (file/module) |
|---|---|
| Validate target URL | `utils/validator.py`, usage in `modules/scanner.py` and `app.py` |
| Run multi-scan concurrently | `VulnerabilityScanner.run_all_scans()` in `modules/scanner.py` (ThreadPoolExecutor) |
| Extract web content + links | `web_scraper.py` (`get_website_text_content`, `extract_urls`, `crawl_website`) |
| AI-assisted analysis | `wolf_api.py` (`WolfAPI.analyze_security`, demo mode fallback) |
| Network/DNS testing | `modules/network_scanner.py` |
| Generate HTML report + charts | `report_generator.py` (`ReportGenerator`) |
| Provide UI workflows | `wolf.py` (Streamlit dashboard) |
| Provide Flask server | `main.py`, `app.py` |

## 3.4 Non-Functional Objectives

- Usability: simple inputs, clear output.
- Reliability: handle timeouts/errors and continue scanning.
- Extensibility: allow adding scanners by adding new modules and wiring them into the coordinator.
- Security: do not store sensitive API keys in code; support environment variables.
