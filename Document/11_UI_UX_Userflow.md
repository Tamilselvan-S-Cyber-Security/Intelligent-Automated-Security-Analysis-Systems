# UI/UX Screens & User Flow

## 11.1 UI Modes in CyberWolfScanner

CyberWolfScanner provides two UI approaches in the repository:

- **Streamlit Dashboard UI**: `wolf.py`
- **Flask Web UI**: templates served by `app.py`

## 11.2 Streamlit UI (`wolf.py`) - User Flow

### Typical Flow

| Step | Screen/Section | User Action | System Action |
|---|---|---|---|
| 1 | Header + sidebar | Open the dashboard | Initializes session state and UI layout |
| 2 | API key section | Provide or generate API key | Stores key in session and enables AI features |
| 3 | Scan selection | Choose scan type | Routes to corresponding analysis function |
| 4 | Target configuration | Provide URL or content | Validates input and prepares scan context |
| 5 | Execution | Click run/scan | Executes scanners / AI analysis |
| 6 | Results view | Review findings | Displays summary, details, charts |
| 7 | Report export | Click generate report | Uses `ReportGenerator` to build HTML |

### UX Characteristics

- Wide layout for dashboards (charts + tables)
- Session-state persistence for keys and settings
- Optional network scanner module availability check

## 11.3 Flask UI (`app.py`) - User Flow

### Typical Flow

| Step | Route | User Action | Backend Action |
|---|---|---|---|
| 1 | `/` | Open home page | Render `index.html` |
| 2 | `/scan` (POST) | Submit URL and scan type | Validate URL, run `VulnerabilityScanner`, collect results |
| 3 | `/scan` response | View results | Show flash messages and results |

## 11.4 Screen Placeholders (For Your Final Report)

If you want this report to contain real screenshots, capture and place them here:

- `Document/assets/streamlit_home.png`
- `Document/assets/flask_scan_form.png`
- `Document/assets/report_preview.png`

Then we can reference them in Markdown.

## 11.5 Accessibility and Usability Notes

- Keep scan configuration minimal and provide safe defaults.
- Provide clear warnings for legal/ethical usage.
- Ensure result formatting highlights severity and recommended fixes.
