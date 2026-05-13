# Existing System Study

## 4.1 Existing Practices (Manual + Tool-based)

Typical existing approaches used by students/organizations for assessing web application security:

- Manual testing using browser developer tools and basic payloads.
- Automated scanners (Burp Suite, OWASP ZAP, Nikto, Nmap).
- Separate tools for:
  - Web vulnerability detection
  - Port scanning
  - DNS/WHOIS reconnaissance
  - Report writing

## 4.2 Limitations in Existing Systems

- Testing is fragmented across multiple tools.
- Output formats differ, making correlation difficult.
- Report creation is often manual and inconsistent.
- Many tools are complex for beginners.
- Coverage depends on user skill, time, and configuration.

## 4.3 Gap Analysis

| Area | Existing Systems | Gap / Issue |
|---|---|---|
| Usability | Powerful but complex tools | Learning curve for non-experts |
| Automation | Some automation exists | Correlation + reporting still manual |
| Reporting | Exports exist but vary | Hard to standardize for project/final report |
| Extensibility | Depends on tool ecosystem | Hard to add custom checks |
| AI guidance | Not always present | Recommendations require expertise |

## 4.4 Why CyberWolfScanner is Needed

CyberWolfScanner aims to unify essential checks into a single platform with:

- Modular scanners (`modules/`)
- A central coordinator (`VulnerabilityScanner`)
- A UI layer (Flask/Streamlit)
- AI-assisted explanation (`WolfAPI`)
- A consistent report format (`ReportGenerator`)
