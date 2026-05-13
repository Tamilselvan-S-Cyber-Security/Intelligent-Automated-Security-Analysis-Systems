# Advantages, Disadvantages & Limitations

## 14.1 Advantages

- **Modular architecture**: New scanners can be added under `modules/` and wired into `VulnerabilityScanner`.
- **Parallel scanning**: Uses `ThreadPoolExecutor` to reduce total scan time.
- **Multiple interfaces**: Streamlit dashboard for interactive use; Flask for web form / API integration.
- **AI-assisted guidance**: `WolfAPI` can provide structured summaries and remediation.
- **Reporting with visualizations**: Security score and charts improve comprehension.
- **Broader coverage**: Includes web vulnerabilities, SSL checks, and network/DNS recon.

## 14.2 Disadvantages

- **False positives/negatives**: Heuristic scanning may miss issues or report non-issues.
- **Limited authenticated crawling**: Complex apps require session handling not fully covered.
- **External AI dependency**: AI features depend on API key/network availability.
- **OS command dependency**: Network module uses ping/traceroute which may be restricted.

## 14.3 Limitations

| Category | Limitation | Impact |
|---|---|---|
| Target complexity | Modern SPAs and heavy JS | crawling/extraction may be incomplete |
| Authentication | Login required scans | requires custom handling |
| Rate limits | Target protections | scans may be blocked |
| Legal constraints | Unauthorized scanning | must be prevented by policy/user |

## 14.4 Risk & Safety Controls (Recommended)

- Always include authorization disclaimer in UI.
- Add domain allowlist for production usage.
- Log scan actions with timestamps and operator identity (future enhancement).
