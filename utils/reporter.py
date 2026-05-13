"""
Vulnerability report generation module
"""

from datetime import datetime
from colorama import Fore, Style

def generate_report(target_url, results):
    """
    Generate a formatted vulnerability report

    Args:
        target_url (str): Target URL that was scanned
        results (dict): Scan results with vulnerability findings

    Returns:
        str: Formatted report text
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Report header
    report = [
        f"{Fore.CYAN}=" * 80,
        f"Intelligent Automated Security Analysis System - Scan Report",
        f"Developed by Security Team - SKP Engineering College, CSE 4th Year",
        f"Generated: {now}",
        f"Target: {target_url}",
        f"=" * 80,
        f"{Style.RESET_ALL}"
    ]

    # Executive summary
    total_vulns = sum(results['summary'].values())
    risk_level = results['summary'].get('risk_level', 'Unknown')
    risk_color = {
        'HIGH': Fore.RED,
        'MEDIUM': Fore.YELLOW,
        'LOW': Fore.GREEN,
        'MINIMAL': Fore.BLUE
    }.get(risk_level, Fore.WHITE)

    report.append(f"\n{Fore.WHITE}EXECUTIVE SUMMARY:{Style.RESET_ALL}")
    report.append(f"Total vulnerabilities found: {total_vulns}")
    report.append(f"Overall risk level: {risk_color}{risk_level}{Style.RESET_ALL}")
    report.append(f"{Fore.CYAN}{'-' * 80}{Style.RESET_ALL}")

    # XSS Vulnerabilities
    if results.get('xss'):
        report.append(f"\n{Fore.RED}CROSS-SITE SCRIPTING (XSS) VULNERABILITIES:{Style.RESET_ALL}")
        report.append(f"Found: {len(results['xss'])}")

        for i, vuln in enumerate(results['xss'], 1):
            report.append(f"\n  {i}. {Fore.YELLOW}Location: {vuln.get('location', 'Unknown')}{Style.RESET_ALL}")
            report.append(f"     Method: {vuln.get('method', 'GET')}")
            report.append(f"     Parameter: {vuln.get('param', 'N/A')}")
            report.append(f"     Payload: {vuln.get('payload', 'N/A')}")
            report.append(f"     URL: {vuln.get('url', 'N/A')}")
    else:
        report.append(f"\n{Fore.GREEN}NO CROSS-SITE SCRIPTING (XSS) VULNERABILITIES FOUND{Style.RESET_ALL}")

    # SQL Injection Vulnerabilities
    if results.get('sqli'):
        report.append(f"\n{Fore.RED}SQL INJECTION VULNERABILITIES:{Style.RESET_ALL}")
        report.append(f"Found: {len(results['sqli'])}")

        for i, vuln in enumerate(results['sqli'], 1):
            report.append(f"\n  {i}. {Fore.YELLOW}Location: {vuln.get('location', 'Unknown')}{Style.RESET_ALL}")
            report.append(f"     Method: {vuln.get('method', 'GET')}")
            report.append(f"     Parameter: {vuln.get('param', 'N/A')}")
            report.append(f"     Payload: {vuln.get('payload', 'N/A')}")
            report.append(f"     Type: {vuln.get('error_type', 'Unknown')}")
            report.append(f"     URL: {vuln.get('url', 'N/A')}")
    else:
        report.append(f"\n{Fore.GREEN}NO SQL INJECTION VULNERABILITIES FOUND{Style.RESET_ALL}")

    # Port Scan Results
    if results.get('ports'):
        report.append(f"\n{Fore.YELLOW}OPEN PORTS AND SERVICES:{Style.RESET_ALL}")
        report.append(f"Found: {len(results['ports'])}")

        for i, port in enumerate(results['ports'], 1):
            report.append(f"\n  {i}. {Fore.CYAN}Port: {port.get('port')}/{port.get('protocol', 'tcp')}{Style.RESET_ALL}")
            report.append(f"     Service: {port.get('service', 'Unknown')}")
            report.append(f"     State: {port.get('state', 'open')}")
    else:
        report.append(f"\n{Fore.GREEN}NO OPEN PORTS DETECTED{Style.RESET_ALL}")

    # Path Scan Results
    if results.get('paths'):
        report.append(f"\n{Fore.YELLOW}VULNERABLE PATHS AND DIRECTORIES:{Style.RESET_ALL}")
        report.append(f"Found: {len(results['paths'])}")

        # Group by risk level
        high_risk = [p for p in results['paths'] if p.get('risk_level') == 'High']
        medium_risk = [p for p in results['paths'] if p.get('risk_level') == 'Medium']

        if high_risk:
            report.append(f"\n  {Fore.RED}HIGH RISK PATHS:{Style.RESET_ALL}")
            for i, path in enumerate(high_risk, 1):
                report.append(f"  {i}. {Fore.RED}{path.get('path')}{Style.RESET_ALL}")
                report.append(f"     URL: {path.get('full_url')}")
                report.append(f"     Status: {path.get('status')} (Code: {path.get('status_code')})")

        if medium_risk:
            report.append(f"\n  {Fore.YELLOW}MEDIUM RISK PATHS:{Style.RESET_ALL}")
            for i, path in enumerate(medium_risk, 1):
                report.append(f"  {i}. {Fore.YELLOW}{path.get('path')}{Style.RESET_ALL}")
                report.append(f"     URL: {path.get('full_url')}")
                report.append(f"     Status: {path.get('status')} (Code: {path.get('status_code')})")
    else:
        report.append(f"\n{Fore.GREEN}NO VULNERABLE PATHS DETECTED{Style.RESET_ALL}")

    # CSRF Vulnerabilities
    if results.get('csrf'):
        report.append(f"\n{Fore.RED}CROSS-SITE REQUEST FORGERY (CSRF) VULNERABILITIES:{Style.RESET_ALL}")
        report.append(f"Found: {len(results['csrf'])}")

        for i, vuln in enumerate(results['csrf'], 1):
            report.append(f"\n  {i}. {Fore.YELLOW}Location: {vuln.get('location', 'Unknown')}{Style.RESET_ALL}")
            report.append(f"     Method: {vuln.get('method', 'POST')}")
            report.append(f"     Form Action: {vuln.get('form_action', 'N/A')}")
            report.append(f"     Has CSRF Token: {vuln.get('has_csrf_token', False)}")
            report.append(f"     Severity: {vuln.get('severity', 'High')}")
    else:
        report.append(f"\n{Fore.GREEN}NO CROSS-SITE REQUEST FORGERY (CSRF) VULNERABILITIES FOUND{Style.RESET_ALL}")

    # JWT Vulnerabilities
    if results.get('jwt'):
        report.append(f"\n{Fore.RED}JSON WEB TOKEN (JWT) VULNERABILITIES:{Style.RESET_ALL}")
        report.append(f"Found: {len(results['jwt'])}")

        for i, vuln in enumerate(results['jwt'], 1):
            report.append(f"\n  {i}. {Fore.YELLOW}Subtype: {vuln.get('subtype', 'Unknown')}{Style.RESET_ALL}")
            report.append(f"     Location: {vuln.get('location', 'N/A')}")
            report.append(f"     Severity: {vuln.get('severity', 'Medium')}")
            report.append(f"     Description: {vuln.get('description', 'N/A')}")
    else:
        report.append(f"\n{Fore.GREEN}NO JSON WEB TOKEN (JWT) VULNERABILITIES FOUND{Style.RESET_ALL}")

    # API Vulnerabilities
    if results.get('api'):
        report.append(f"\n{Fore.RED}API SECURITY VULNERABILITIES:{Style.RESET_ALL}")
        report.append(f"Found: {len(results['api'])}")

        for i, vuln in enumerate(results['api'], 1):
            report.append(f"\n  {i}. {Fore.YELLOW}Subtype: {vuln.get('subtype', 'Unknown')}{Style.RESET_ALL}")
            report.append(f"     Endpoint: {vuln.get('endpoint', 'N/A')}")
            report.append(f"     Severity: {vuln.get('severity', 'Medium')}")
            report.append(f"     Description: {vuln.get('description', 'N/A')}")
    else:
        report.append(f"\n{Fore.GREEN}NO API SECURITY VULNERABILITIES FOUND{Style.RESET_ALL}")

    # Brute Force Vulnerabilities
    if results.get('bruteforce'):
        report.append(f"\n{Fore.RED}BRUTE FORCE VULNERABILITIES:{Style.RESET_ALL}")
        report.append(f"Found: {len(results['bruteforce'])}")

        for i, vuln in enumerate(results['bruteforce'], 1):
            report.append(f"\n  {i}. {Fore.YELLOW}Subtype: {vuln.get('subtype', 'Unknown')}{Style.RESET_ALL}")
            report.append(f"     URL: {vuln.get('url', 'N/A')}")
            report.append(f"     Severity: {vuln.get('severity', 'High')}")
            report.append(f"     Description: {vuln.get('description', 'N/A')}")
    else:
        report.append(f"\n{Fore.GREEN}NO BRUTE FORCE VULNERABILITIES FOUND{Style.RESET_ALL}")

    # SSL/TLS Vulnerabilities
    if results.get('ssl'):
        report.append(f"\n{Fore.RED}SSL/TLS VULNERABILITIES:{Style.RESET_ALL}")
        report.append(f"Found: {len(results['ssl'])}")

        for i, vuln in enumerate(results['ssl'], 1):
            report.append(f"\n  {i}. {Fore.YELLOW}Subtype: {vuln.get('subtype', 'Unknown')}{Style.RESET_ALL}")
            report.append(f"     Hostname: {vuln.get('hostname', 'N/A')}")
            report.append(f"     Port: {vuln.get('port', 'N/A')}")
            report.append(f"     Severity: {vuln.get('severity', 'Medium')}")
            report.append(f"     Description: {vuln.get('description', 'N/A')}")
    else:
        report.append(f"\n{Fore.GREEN}NO SSL/TLS VULNERABILITIES FOUND{Style.RESET_ALL}")

    # Remediation recommendations
    report.append(f"\n{Fore.CYAN}REMEDIATION RECOMMENDATIONS:{Style.RESET_ALL}")

    if results.get('xss'):
        report.append(f"\n{Fore.WHITE}For XSS vulnerabilities:{Style.RESET_ALL}")
        report.append("  - Implement proper input validation and sanitization")
        report.append("  - Use Content-Security-Policy headers")
        report.append("  - Apply output encoding when rendering user input")
        report.append("  - Consider using frameworks with built-in XSS protection")

    if results.get('sqli'):
        report.append(f"\n{Fore.WHITE}For SQL Injection vulnerabilities:{Style.RESET_ALL}")
        report.append("  - Use parameterized queries or prepared statements")
        report.append("  - Implement proper input validation and sanitization")
        report.append("  - Apply the principle of least privilege for database users")
        report.append("  - Consider using ORM frameworks")

    if results.get('ports'):
        report.append(f"\n{Fore.WHITE}For open ports:{Style.RESET_ALL}")
        report.append("  - Close unnecessary ports and services")
        report.append("  - Implement proper firewall rules")
        report.append("  - Keep services updated to the latest secure versions")
        report.append("  - Use network segmentation where possible")

    if results.get('paths'):
        report.append(f"\n{Fore.WHITE}For vulnerable paths:{Style.RESET_ALL}")
        report.append("  - Remove or secure sensitive files from web-accessible directories")
        report.append("  - Implement proper access controls and authentication")
        report.append("  - Configure web server to deny access to sensitive directories")
        report.append("  - Use .htaccess or web.config files to restrict access")

    if results.get('csrf'):
        report.append(f"\n{Fore.WHITE}For CSRF vulnerabilities:{Style.RESET_ALL}")
        report.append("  - Implement anti-CSRF tokens in all forms")
        report.append("  - Use the SameSite cookie attribute")
        report.append("  - Implement the 'Origin' and 'Referer' header validation")
        report.append("  - Consider using frameworks with built-in CSRF protection")

    if results.get('jwt'):
        report.append(f"\n{Fore.WHITE}For JWT vulnerabilities:{Style.RESET_ALL}")
        report.append("  - Use strong signing algorithms (RS256, ES256)")
        report.append("  - Never use the 'none' algorithm")
        report.append("  - Include expiration times in tokens")
        report.append("  - Validate all claims and headers")
        report.append("  - Use secure key management practices")

    if results.get('api'):
        report.append(f"\n{Fore.WHITE}For API vulnerabilities:{Style.RESET_ALL}")
        report.append("  - Implement proper authentication and authorization")
        report.append("  - Use rate limiting to prevent abuse")
        report.append("  - Validate and sanitize all inputs")
        report.append("  - Implement proper error handling")
        report.append("  - Use HTTPS for all API communications")

    if results.get('bruteforce'):
        report.append(f"\n{Fore.WHITE}For brute force vulnerabilities:{Style.RESET_ALL}")
        report.append("  - Implement account lockout after failed attempts")
        report.append("  - Use CAPTCHA or other anti-automation measures")
        report.append("  - Implement rate limiting on authentication endpoints")
        report.append("  - Use strong password policies")
        report.append("  - Consider multi-factor authentication")

    if results.get('ssl'):
        report.append(f"\n{Fore.WHITE}For SSL/TLS vulnerabilities:{Style.RESET_ALL}")
        report.append("  - Disable outdated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)")
        report.append("  - Use strong cipher suites and disable weak ciphers")
        report.append("  - Keep certificates up to date")
        report.append("  - Use proper certificate validation")
        report.append("  - Implement HTTP Strict Transport Security (HSTS)")

    # Report footer
    report.append(f"\n{Fore.CYAN}{'=' * 80}")
    report.append(f"End of Report - Developed by Security Team - SKP Engineering College, CSE 4th Year")
    report.append(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}\n")

    return "\n".join(report)
