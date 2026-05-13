# Abstract

Modern web applications and software systems face an expanding threat landscape, including injection attacks, broken authentication, insecure configuration, exposed services, and weak transport-layer security. Manual security testing is time-consuming and requires expert knowledge. This project presents **CyberWolfScanner**, an **Intelligent Automated Security Analysis System** that performs automated, modular security scanning for websites and applications, and assists the user in generating structured security reports with prioritized findings and actionable remediation.

The system provides two primary usage modes:

- A **Flask-based web application** (`main.py` -> `app.py`) that receives scan requests, validates inputs, runs modular scans, and returns results.
- A **Streamlit dashboard UI** (`wolf.py`) that offers interactive analysis workflows including AI-assisted threat analysis, web application scanning, attack simulation support, and integrated report generation.

CyberWolfScanner integrates:

- **Deterministic scanners** (XSS, SQL injection, ports/services, path discovery, misconfiguration checks, SSL checks, and more) via the `modules/` package and `VulnerabilityScanner` coordinator.
- **AI-assisted analysis** via `WolfAPI` (Gemini-backed or demo mode) to summarize risk and recommend mitigations.
- **Reporting pipeline** through `ReportGenerator` that produces an HTML report including charts and visual indicators (security score gauge, issue distributions, category counts).

The final output is a detailed report that supports security assessment, triage, and remediation planning, making the tool suitable for academic, prototype, and controlled testing environments.

---

## Keywords

Web Vulnerability Scanning, OWASP, XSS, SQL Injection, Automated Security Testing, AI-Assisted Security Analysis, Flask, Streamlit, Reporting, Risk Assessment
