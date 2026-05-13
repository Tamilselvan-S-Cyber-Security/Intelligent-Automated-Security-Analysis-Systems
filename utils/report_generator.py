"""
Advanced report generation module with support for multiple output formats
"""

import os
import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional, List

logger = logging.getLogger('CyberWolf.ReportGenerator')

class ReportGenerator:
    """
    Advanced report generator for CyberWolf vulnerability scanner
    Supports multiple output formats including text, HTML, and PDF
    """
    
    def __init__(self, target_url: str, scan_results: Dict[str, Any], 
                 output_dir: str = "./reports", include_evidence: bool = True):
        """
        Initialize the report generator
        
        Args:
            target_url (str): Target URL that was scanned
            scan_results (dict): Scan results with vulnerability findings
            output_dir (str): Directory to save reports to
            include_evidence (bool): Whether to include detailed evidence in reports
        """
        self.target_url = target_url
        self.results = scan_results
        self.output_dir = output_dir
        self.include_evidence = include_evidence
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.filename_base = f"cyberwolf_report_{self.timestamp}"
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                logger.info(f"Created report directory: {output_dir}")
            except Exception as e:
                logger.error(f"Error creating output directory: {str(e)}")
    
    def generate_text_report(self) -> str:
        """
        Generate text report of vulnerabilities
        
        Returns:
            str: Path to the generated report file
        """
        # Get the report content
        report_content = self._generate_text_content()
        
        # Save to file
        output_path = os.path.join(self.output_dir, f"{self.filename_base}.txt")
        try:
            with open(output_path, 'w') as f:
                f.write(report_content)
            logger.info(f"Text report saved to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error saving text report: {str(e)}")
            return ""
    
    def generate_html_report(self) -> str:
        """
        Generate HTML report of vulnerabilities
        
        Returns:
            str: Path to the generated report file
        """
        # Generate the HTML content
        html_content = self._generate_html_content()
        
        # Save to file
        output_path = os.path.join(self.output_dir, f"{self.filename_base}.html")
        try:
            with open(output_path, 'w') as f:
                f.write(html_content)
            logger.info(f"HTML report saved to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error saving HTML report: {str(e)}")
            return ""
    
    def generate_pdf_report(self) -> str:
        """
        Generate PDF report of vulnerabilities
        
        Returns:
            str: Path to the generated report file
        """
        try:
            # Generate HTML content first (for conversion to PDF)
            html_content = self._generate_html_content()
            
            # Use a PDF generation library when available
            # For now, we'll use a simple HTML-to-PDF conversion approach
            # using the pdfkit library (if available)
            try:
                import pdfkit
                output_path = os.path.join(self.output_dir, f"{self.filename_base}.pdf")
                
                # Configure PDF options
                options = {
                    'page-size': 'A4',
                    'margin-top': '20mm',
                    'margin-right': '20mm',
                    'margin-bottom': '20mm',
                    'margin-left': '20mm',
                    'encoding': 'UTF-8',
                    'title': f'CyberWolf Security Scan Report - {self.target_url}',
                    'footer-right': '[page] of [topage]',
                    'footer-left': f'CyberWolf - {datetime.now().strftime("%Y-%m-%d")}',
                }
                
                # Generate the PDF
                pdfkit.from_string(html_content, output_path, options=options)
                logger.info(f"PDF report saved to {output_path}")
                return output_path
            except ImportError:
                logger.warning("pdfkit library not available, falling back to HTML report")
                # Fall back to HTML report if pdfkit is not available
                return self.generate_html_report()
        except Exception as e:
            logger.error(f"Error generating PDF report: {str(e)}")
            return ""
    
    def generate_json_report(self) -> str:
        """
        Generate JSON report of vulnerabilities
        
        Returns:
            str: Path to the generated report file
        """
        # Prepare the JSON data
        report_data = {
            "target_url": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "scan_results": self.results,
            "generated_by": "CyberWolf Scanner"
        }
        
        # Save to file
        output_path = os.path.join(self.output_dir, f"{self.filename_base}.json")
        try:
            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            logger.info(f"JSON report saved to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error saving JSON report: {str(e)}")
            return ""
    
    def generate_all_formats(self) -> Dict[str, str]:
        """
        Generate reports in all available formats
        
        Returns:
            dict: Dictionary mapping format names to output file paths
        """
        return {
            "text": self.generate_text_report(),
            "html": self.generate_html_report(),
            "pdf": self.generate_pdf_report(),
            "json": self.generate_json_report()
        }
    
    def _generate_text_content(self) -> str:
        """
        Generate the text content for the report
        
        Returns:
            str: Text report content
        """
        # Initialize the report content
        report = []
        
        # Report header
        report.append("=" * 80)
        report.append("CyberWolf Security Scan Report")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Target: {self.target_url}")
        report.append("=" * 80)
        
        # Executive summary
        total_vulns = sum(self.results['summary'].values()) if 'summary' in self.results else 0
        risk_level = self.results.get('summary', {}).get('risk_level', 'Unknown')
        
        report.append("\nEXECUTIVE SUMMARY:")
        report.append(f"Total vulnerabilities found: {total_vulns}")
        report.append(f"Overall risk level: {risk_level}")
        report.append("-" * 80)
        
        # Add vulnerability sections for each type
        report.extend(self._generate_text_xss_section())
        report.extend(self._generate_text_sqli_section())
        report.extend(self._generate_text_ports_section())
        report.extend(self._generate_text_paths_section())
        report.extend(self._generate_text_misconfig_section())
        
        # Add remediation recommendations
        report.extend(self._generate_text_recommendations())
        
        # Report footer
        report.append("\n" + "=" * 80)
        report.append("End of Report - The Developed By CyberWolf Team")
        report.append("=" * 80 + "\n")
        
        return "\n".join(report)
    
    def _generate_text_xss_section(self) -> List[str]:
        """Generate XSS vulnerability section for text report"""
        section = []
        
        # XSS Vulnerabilities
        if 'xss' in self.results and self.results['xss']:
            section.append("\nCROSS-SITE SCRIPTING (XSS) VULNERABILITIES:")
            section.append(f"Found: {len(self.results['xss'])}")
            
            for i, vuln in enumerate(self.results['xss'], 1):
                section.append(f"\n  {i}. Location: {vuln.get('location', 'Unknown')}")
                section.append(f"     Method: {vuln.get('method', 'GET')}")
                section.append(f"     Parameter: {vuln.get('param', 'N/A')}")
                
                # Include evidence if requested
                if self.include_evidence:
                    section.append(f"     Payload: {vuln.get('payload', 'N/A')}")
                    section.append(f"     URL: {vuln.get('url', 'N/A')}")
        else:
            section.append("\nNO CROSS-SITE SCRIPTING (XSS) VULNERABILITIES FOUND")
        
        return section
    
    def _generate_text_sqli_section(self) -> List[str]:
        """Generate SQL Injection vulnerability section for text report"""
        section = []
        
        # SQL Injection Vulnerabilities
        if 'sqli' in self.results and self.results['sqli']:
            section.append("\nSQL INJECTION VULNERABILITIES:")
            section.append(f"Found: {len(self.results['sqli'])}")
            
            for i, vuln in enumerate(self.results['sqli'], 1):
                section.append(f"\n  {i}. Location: {vuln.get('location', 'Unknown')}")
                section.append(f"     Method: {vuln.get('method', 'GET')}")
                section.append(f"     Parameter: {vuln.get('param', 'N/A')}")
                section.append(f"     Type: {vuln.get('error_type', 'Unknown')}")
                
                # Include evidence if requested
                if self.include_evidence:
                    section.append(f"     Payload: {vuln.get('payload', 'N/A')}")
                    section.append(f"     URL: {vuln.get('url', 'N/A')}")
        else:
            section.append("\nNO SQL INJECTION VULNERABILITIES FOUND")
        
        return section
    
    def _generate_text_ports_section(self) -> List[str]:
        """Generate open ports section for text report"""
        section = []
        
        # Port Scan Results
        if 'ports' in self.results and self.results['ports']:
            section.append("\nOPEN PORTS AND SERVICES:")
            section.append(f"Found: {len(self.results['ports'])}")
            
            for i, port in enumerate(self.results['ports'], 1):
                section.append(f"\n  {i}. Port: {port.get('port')}/{port.get('protocol', 'tcp')}")
                section.append(f"     Service: {port.get('service', 'Unknown')}")
                section.append(f"     State: {port.get('state', 'open')}")
        else:
            section.append("\nNO OPEN PORTS DETECTED")
        
        return section
    
    def _generate_text_paths_section(self) -> List[str]:
        """Generate vulnerable paths section for text report"""
        section = []
        
        # Path Scan Results
        if 'paths' in self.results and self.results['paths']:
            section.append("\nVULNERABLE PATHS AND DIRECTORIES:")
            section.append(f"Found: {len(self.results['paths'])}")
            
            # Group by risk level
            high_risk = [p for p in self.results['paths'] if p.get('risk_level') == 'High']
            medium_risk = [p for p in self.results['paths'] if p.get('risk_level') == 'Medium']
            low_risk = [p for p in self.results['paths'] if p.get('risk_level') not in ['High', 'Medium']]
            
            if high_risk:
                section.append("\n  HIGH RISK PATHS:")
                for i, path in enumerate(high_risk, 1):
                    section.append(f"  {i}. {path.get('path')}")
                    section.append(f"     URL: {path.get('full_url')}")
                    section.append(f"     Status: {path.get('status')} (Code: {path.get('status_code')})")
            
            if medium_risk:
                section.append("\n  MEDIUM RISK PATHS:")
                for i, path in enumerate(medium_risk, 1):
                    section.append(f"  {i}. {path.get('path')}")
                    section.append(f"     URL: {path.get('full_url')}")
                    section.append(f"     Status: {path.get('status')} (Code: {path.get('status_code')})")
                    
            if low_risk and self.include_evidence:
                section.append("\n  LOW RISK PATHS:")
                for i, path in enumerate(low_risk, 1):
                    section.append(f"  {i}. {path.get('path')}")
                    section.append(f"     URL: {path.get('full_url')}")
                    section.append(f"     Status: {path.get('status')} (Code: {path.get('status_code')})")
        else:
            section.append("\nNO VULNERABLE PATHS DETECTED")
        
        return section
    
    def _generate_text_misconfig_section(self) -> List[str]:
        """Generate security misconfiguration section for text report"""
        section = []
        
        # Security Misconfiguration Results
        if 'misconfig' in self.results and self.results['misconfig']:
            section.append("\nSECURITY MISCONFIGURATIONS:")
            section.append(f"Found: {len(self.results['misconfig'])}")
            
            # Group by type
            header_vulns = [m for m in self.results['misconfig'] if m.get('type') == 'missing_security_header']
            cookie_vulns = [m for m in self.results['misconfig'] if m.get('type') == 'insecure_cookie']
            info_vulns = [m for m in self.results['misconfig'] if m.get('type') == 'info_disclosure']
            resource_vulns = [m for m in self.results['misconfig'] if m.get('type') == 'default_resource']
            other_vulns = [m for m in self.results['misconfig'] if m.get('type') not in ['missing_security_header', 'insecure_cookie', 'info_disclosure', 'default_resource']]
            
            # Security Headers
            if header_vulns:
                section.append("\n  MISSING SECURITY HEADERS:")
                for i, vuln in enumerate(header_vulns, 1):
                    section.append(f"  {i}. {vuln.get('header')}")
                    section.append(f"     Description: {vuln.get('description')}")
                    section.append(f"     Severity: {vuln.get('severity')}")
                    section.append(f"     Mitigation: {vuln.get('mitigation')}")
            
            # Insecure Cookies
            if cookie_vulns:
                section.append("\n  INSECURE COOKIES:")
                for i, vuln in enumerate(cookie_vulns, 1):
                    section.append(f"  {i}. {vuln.get('description')}")
                    section.append(f"     Severity: {vuln.get('severity')}")
                    section.append(f"     Mitigation: {vuln.get('mitigation')}")
                    if self.include_evidence and 'evidence' in vuln:
                        section.append(f"     Evidence: {vuln.get('evidence')}")
            
            # Information Disclosure
            if info_vulns:
                section.append("\n  INFORMATION DISCLOSURE:")
                for i, vuln in enumerate(info_vulns, 1):
                    section.append(f"  {i}. {vuln.get('header', 'Unknown')} header")
                    section.append(f"     Description: {vuln.get('description')}")
                    section.append(f"     Severity: {vuln.get('severity')}")
                    section.append(f"     Mitigation: {vuln.get('mitigation')}")
                    if self.include_evidence and 'evidence' in vuln:
                        section.append(f"     Evidence: {vuln.get('evidence')}")
            
            # Default Resources
            if resource_vulns:
                section.append("\n  SENSITIVE RESOURCES:")
                for i, vuln in enumerate(resource_vulns, 1):
                    section.append(f"  {i}. {vuln.get('description')}")
                    section.append(f"     URL: {vuln.get('url')}")
                    section.append(f"     Severity: {vuln.get('severity')}")
                    section.append(f"     Mitigation: {vuln.get('mitigation')}")
            
            # Other Vulnerabilities
            if other_vulns:
                section.append("\n  OTHER MISCONFIGURATIONS:")
                for i, vuln in enumerate(other_vulns, 1):
                    section.append(f"  {i}. Type: {vuln.get('type')}")
                    section.append(f"     Description: {vuln.get('description')}")
                    section.append(f"     Severity: {vuln.get('severity')}")
                    section.append(f"     Mitigation: {vuln.get('mitigation')}")
        else:
            section.append("\nNO SECURITY MISCONFIGURATIONS DETECTED")
        
        return section
    
    def _generate_text_recommendations(self) -> List[str]:
        """Generate remediation recommendations section for text report"""
        recommendations = []
        
        # Remediation recommendations
        recommendations.append("\nREMEDIATION RECOMMENDATIONS:")
        
        # XSS Recommendations
        if 'xss' in self.results and self.results['xss']:
            recommendations.append("\nFor XSS vulnerabilities:")
            recommendations.append("  - Implement proper input validation and sanitization")
            recommendations.append("  - Use Content-Security-Policy headers")
            recommendations.append("  - Apply output encoding when rendering user input")
            recommendations.append("  - Consider using frameworks with built-in XSS protection")
        
        # SQLi Recommendations
        if 'sqli' in self.results and self.results['sqli']:
            recommendations.append("\nFor SQL Injection vulnerabilities:")
            recommendations.append("  - Use parameterized queries or prepared statements")
            recommendations.append("  - Implement proper input validation and sanitization")
            recommendations.append("  - Apply the principle of least privilege for database users")
            recommendations.append("  - Consider using ORM frameworks")
        
        # Port Recommendations
        if 'ports' in self.results and self.results['ports']:
            recommendations.append("\nFor open ports:")
            recommendations.append("  - Close unnecessary ports and services")
            recommendations.append("  - Implement proper firewall rules")
            recommendations.append("  - Keep services updated to the latest secure versions")
            recommendations.append("  - Use network segmentation where possible")
        
        # Path Recommendations
        if 'paths' in self.results and self.results['paths']:
            recommendations.append("\nFor vulnerable paths:")
            recommendations.append("  - Remove or secure sensitive files from web-accessible directories")
            recommendations.append("  - Implement proper access controls and authentication")
            recommendations.append("  - Configure web server to deny access to sensitive directories")
            recommendations.append("  - Use .htaccess or web.config files to restrict access")
            
        # Misconfiguration Recommendations
        if 'misconfig' in self.results and self.results['misconfig']:
            recommendations.append("\nFor security misconfigurations:")
            recommendations.append("  - Implement all recommended security headers")
            recommendations.append("  - Ensure cookies have proper security flags (HttpOnly, Secure, SameSite)")
            recommendations.append("  - Remove or mask server information disclosure")
            recommendations.append("  - Configure error handling to avoid exposing sensitive details")
            recommendations.append("  - Disable debug/development modes in production environments")
        
        return recommendations
    
    def _generate_html_content(self) -> str:
        """
        Generate the HTML content for the report
        
        Returns:
            str: HTML report content
        """
        # Calculate summary statistics
        total_vulns = sum(self.results['summary'].values()) if 'summary' in self.results else 0
        risk_level = self.results.get('summary', {}).get('risk_level', 'Unknown')
        risk_class = {
            'HIGH': 'danger',
            'MEDIUM': 'warning',
            'LOW': 'info',
            'MINIMAL': 'success'
        }.get(risk_level, 'secondary')
        
        # Current date/time
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Start building HTML content
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberWolf Security Scan Report - {self.target_url}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        h1, h2, h3, h4 {{
            color: #212529;
        }}
        .header {{
            border-bottom: 2px solid #dee2e6;
            margin-bottom: 30px;
            padding-bottom: 10px;
        }}
        .footer {{
            border-top: 1px solid #dee2e6;
            margin-top: 50px;
            padding-top: 20px;
            text-align: center;
            font-size: 0.9em;
            color: #6c757d;
        }}
        .summary {{
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 30px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            border: 1px solid #dee2e6;
            padding: 8px 12px;
            text-align: left;
        }}
        th {{
            background-color: #e9ecef;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .badge {{
            display: inline-block;
            padding: 0.25em 0.6em;
            font-size: 0.75em;
            font-weight: 700;
            text-align: center;
            white-space: nowrap;
            vertical-align: baseline;
            border-radius: 0.25rem;
            color: white;
        }}
        .badge-danger {{
            background-color: #dc3545;
        }}
        .badge-warning {{
            background-color: #ffc107;
            color: #212529;
        }}
        .badge-info {{
            background-color: #17a2b8;
        }}
        .badge-success {{
            background-color: #28a745;
        }}
        .badge-secondary {{
            background-color: #6c757d;
        }}
        .alert {{
            padding: 15px;
            margin-bottom: 20px;
            border: 1px solid transparent;
            border-radius: 4px;
        }}
        .alert-danger {{
            color: #721c24;
            background-color: #f8d7da;
            border-color: #f5c6cb;
        }}
        .alert-warning {{
            color: #856404;
            background-color: #fff3cd;
            border-color: #ffeeba;
        }}
        .alert-info {{
            color: #0c5460;
            background-color: #d1ecf1;
            border-color: #bee5eb;
        }}
        .alert-success {{
            color: #155724;
            background-color: #d4edda;
            border-color: #c3e6cb;
        }}
        .recommendations {{
            background-color: #e9ecef;
            border-radius: 5px;
            padding: 20px;
            margin-top: 30px;
        }}
        .evidence {{
            font-family: monospace;
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            white-space: pre-wrap;
            word-break: break-all;
            margin-top: 10px;
        }}
        section {{
            margin-bottom: 40px;
        }}
        .collapse-btn {{
            cursor: pointer;
            padding: 5px 10px;
            background-color: #e9ecef;
            border: none;
            border-radius: 3px;
        }}
        .collapse-content {{
            display: none;
            padding: 10px;
            border: 1px solid #dee2e6;
            border-radius: 3px;
            margin-top: 10px;
        }}
    </style>
    <script>
        function toggleCollapse(id) {{
            const content = document.getElementById(id);
            if (content.style.display === "block") {{
                content.style.display = "none";
            }} else {{
                content.style.display = "block";
            }}
        }}
    </script>
</head>
<body>
    <div class="header">
        <h1>CyberWolf Security Scan Report</h1>
        <p>Target URL: <strong>{self.target_url}</strong></p>
        <p>Generated: {now}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="alert alert-{risk_class}">
            <h3>Risk Level: {risk_level}</h3>
            <p>Total vulnerabilities found: {total_vulns}</p>
        </div>
    </div>
"""
        
        # Add XSS Vulnerabilities Section
        html += self._generate_html_xss_section()
        
        # Add SQL Injection Vulnerabilities Section
        html += self._generate_html_sqli_section()
        
        # Add Open Ports Section
        html += self._generate_html_ports_section()
        
        # Add Path Vulnerabilities Section
        html += self._generate_html_paths_section()
        
        # Add Security Misconfigurations Section
        html += self._generate_html_misconfig_section()
        
        # Add Recommendations Section
        html += self._generate_html_recommendations()
        
        # Add Footer
        html += """
    <div class="footer">
        <p>Generated by CyberWolf Vulnerability Scanner</p>
        <p>Developed By CyberWolf Team</p>
    </div>
</body>
</html>
"""
        
        return html

    def _generate_html_xss_section(self) -> str:
        """Generate XSS vulnerability HTML section"""
        section = """
    <section id="xss-vulnerabilities">
        <h2>Cross-Site Scripting (XSS) Vulnerabilities</h2>
"""
        
        if 'xss' in self.results and self.results['xss']:
            vulns = self.results['xss']
            badge_class = "danger" if vulns else "success"
            section += f"""
        <div class="alert alert-{badge_class}">
            <p>Found: <strong>{len(vulns)}</strong> XSS vulnerabilities</p>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Location</th>
                    <th>Method</th>
                    <th>Parameter</th>
                    <th>Severity</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
"""
            
            for i, vuln in enumerate(vulns, 1):
                severity = vuln.get('severity', 'Medium')
                severity_class = {
                    'High': 'danger',
                    'Medium': 'warning',
                    'Low': 'info'
                }.get(severity, 'secondary')
                
                details_id = f"xss-details-{i}"
                
                section += f"""
                <tr>
                    <td>{i}</td>
                    <td>{vuln.get('location', 'Unknown')}</td>
                    <td>{vuln.get('method', 'GET')}</td>
                    <td>{vuln.get('param', 'N/A')}</td>
                    <td><span class="badge badge-{severity_class}">{severity}</span></td>
                    <td>
                        <button class="collapse-btn" onclick="toggleCollapse('{details_id}')">View Details</button>
                        <div id="{details_id}" class="collapse-content">
"""
                
                if self.include_evidence:
                    section += f"""
                            <p><strong>Payload:</strong></p>
                            <div class="evidence">{vuln.get('payload', 'N/A')}</div>
                            <p><strong>URL:</strong></p>
                            <div class="evidence">{vuln.get('url', 'N/A')}</div>
"""
                
                section += """
                        </div>
                    </td>
                </tr>
"""
            
            section += """
            </tbody>
        </table>
"""
        else:
            section += """
        <div class="alert alert-success">
            <p>No Cross-Site Scripting (XSS) vulnerabilities found</p>
        </div>
"""
        
        section += """
    </section>
"""
        return section
    
    def _generate_html_sqli_section(self) -> str:
        """Generate SQL Injection vulnerability HTML section"""
        section = """
    <section id="sqli-vulnerabilities">
        <h2>SQL Injection Vulnerabilities</h2>
"""
        
        if 'sqli' in self.results and self.results['sqli']:
            vulns = self.results['sqli']
            badge_class = "danger" if vulns else "success"
            section += f"""
        <div class="alert alert-{badge_class}">
            <p>Found: <strong>{len(vulns)}</strong> SQL Injection vulnerabilities</p>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Location</th>
                    <th>Method</th>
                    <th>Parameter</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
"""
            
            for i, vuln in enumerate(vulns, 1):
                severity = vuln.get('severity', 'High')
                severity_class = {
                    'High': 'danger',
                    'Medium': 'warning',
                    'Low': 'info'
                }.get(severity, 'danger')
                
                details_id = f"sqli-details-{i}"
                
                section += f"""
                <tr>
                    <td>{i}</td>
                    <td>{vuln.get('location', 'Unknown')}</td>
                    <td>{vuln.get('method', 'GET')}</td>
                    <td>{vuln.get('param', 'N/A')}</td>
                    <td>{vuln.get('error_type', 'Unknown')}</td>
                    <td><span class="badge badge-{severity_class}">{severity}</span></td>
                    <td>
                        <button class="collapse-btn" onclick="toggleCollapse('{details_id}')">View Details</button>
                        <div id="{details_id}" class="collapse-content">
"""
                
                if self.include_evidence:
                    section += f"""
                            <p><strong>Payload:</strong></p>
                            <div class="evidence">{vuln.get('payload', 'N/A')}</div>
                            <p><strong>URL:</strong></p>
                            <div class="evidence">{vuln.get('url', 'N/A')}</div>
"""
                
                section += """
                        </div>
                    </td>
                </tr>
"""
            
            section += """
            </tbody>
        </table>
"""
        else:
            section += """
        <div class="alert alert-success">
            <p>No SQL Injection vulnerabilities found</p>
        </div>
"""
        
        section += """
    </section>
"""
        return section
    
    def _generate_html_ports_section(self) -> str:
        """Generate open ports HTML section"""
        section = """
    <section id="open-ports">
        <h2>Open Ports and Services</h2>
"""
        
        if 'ports' in self.results and self.results['ports']:
            ports = self.results['ports']
            alert_class = "warning" if ports else "success"
            section += f"""
        <div class="alert alert-{alert_class}">
            <p>Found: <strong>{len(ports)}</strong> open ports</p>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>State</th>
                </tr>
            </thead>
            <tbody>
"""
            
            for i, port in enumerate(ports, 1):
                section += f"""
                <tr>
                    <td>{i}</td>
                    <td>{port.get('port')}</td>
                    <td>{port.get('protocol', 'tcp')}</td>
                    <td>{port.get('service', 'Unknown')}</td>
                    <td>{port.get('state', 'open')}</td>
                </tr>
"""
            
            section += """
            </tbody>
        </table>
"""
        else:
            section += """
        <div class="alert alert-success">
            <p>No open ports detected</p>
        </div>
"""
        
        section += """
    </section>
"""
        return section
    
    def _generate_html_paths_section(self) -> str:
        """Generate vulnerable paths HTML section"""
        section = """
    <section id="vulnerable-paths">
        <h2>Vulnerable Paths and Directories</h2>
"""
        
        if 'paths' in self.results and self.results['paths']:
            paths = self.results['paths']
            alert_class = "warning" if paths else "success"
            
            # Group by risk level
            high_risk = [p for p in paths if p.get('risk_level') == 'High']
            medium_risk = [p for p in paths if p.get('risk_level') == 'Medium']
            low_risk = [p for p in paths if p.get('risk_level') not in ['High', 'Medium']]
            
            section += f"""
        <div class="alert alert-{alert_class}">
            <p>Found: <strong>{len(paths)}</strong> vulnerable paths</p>
        </div>
"""
            
            # High Risk Paths
            if high_risk:
                section += """
        <h3>High Risk Paths</h3>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Path</th>
                    <th>Status</th>
                    <th>URL</th>
                </tr>
            </thead>
            <tbody>
"""
                
                for i, path in enumerate(high_risk, 1):
                    section += f"""
                <tr>
                    <td>{i}</td>
                    <td>{path.get('path')}</td>
                    <td>{path.get('status')} (Code: {path.get('status_code')})</td>
                    <td><a href="{path.get('full_url')}" target="_blank">{path.get('full_url')}</a></td>
                </tr>
"""
                
                section += """
            </tbody>
        </table>
"""
            
            # Medium Risk Paths
            if medium_risk:
                section += """
        <h3>Medium Risk Paths</h3>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Path</th>
                    <th>Status</th>
                    <th>URL</th>
                </tr>
            </thead>
            <tbody>
"""
                
                for i, path in enumerate(medium_risk, 1):
                    section += f"""
                <tr>
                    <td>{i}</td>
                    <td>{path.get('path')}</td>
                    <td>{path.get('status')} (Code: {path.get('status_code')})</td>
                    <td><a href="{path.get('full_url')}" target="_blank">{path.get('full_url')}</a></td>
                </tr>
"""
                
                section += """
            </tbody>
        </table>
"""
            
            # Low Risk Paths (only if include_evidence is True)
            if low_risk and self.include_evidence:
                section += """
        <h3>Low Risk Paths</h3>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Path</th>
                    <th>Status</th>
                    <th>URL</th>
                </tr>
            </thead>
            <tbody>
"""
                
                for i, path in enumerate(low_risk, 1):
                    section += f"""
                <tr>
                    <td>{i}</td>
                    <td>{path.get('path')}</td>
                    <td>{path.get('status')} (Code: {path.get('status_code')})</td>
                    <td><a href="{path.get('full_url')}" target="_blank">{path.get('full_url')}</a></td>
                </tr>
"""
                
                section += """
            </tbody>
        </table>
"""
            
        else:
            section += """
        <div class="alert alert-success">
            <p>No vulnerable paths detected</p>
        </div>
"""
        
        section += """
    </section>
"""
        return section
    
    def _generate_html_misconfig_section(self) -> str:
        """Generate security misconfiguration HTML section"""
        section = """
    <section id="security-misconfigurations">
        <h2>Security Misconfigurations</h2>
"""
        
        if 'misconfig' in self.results and self.results['misconfig']:
            misconfigs = self.results['misconfig']
            alert_class = "warning" if misconfigs else "success"
            
            # Group by type
            header_vulns = [m for m in misconfigs if m.get('type') == 'missing_security_header']
            cookie_vulns = [m for m in misconfigs if m.get('type') == 'insecure_cookie']
            info_vulns = [m for m in misconfigs if m.get('type') == 'info_disclosure']
            resource_vulns = [m for m in misconfigs if m.get('type') == 'default_resource']
            other_vulns = [m for m in misconfigs if m.get('type') not in ['missing_security_header', 'insecure_cookie', 'info_disclosure', 'default_resource']]
            
            section += f"""
        <div class="alert alert-{alert_class}">
            <p>Found: <strong>{len(misconfigs)}</strong> security misconfigurations</p>
        </div>
"""
            
            # Missing Security Headers
            if header_vulns:
                section += """
        <h3>Missing Security Headers</h3>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Header</th>
                    <th>Description</th>
                    <th>Severity</th>
                    <th>Mitigation</th>
                </tr>
            </thead>
            <tbody>
"""
                
                for i, vuln in enumerate(header_vulns, 1):
                    severity = vuln.get('severity', 'Medium')
                    severity_class = {
                        'High': 'danger',
                        'Medium': 'warning',
                        'Low': 'info'
                    }.get(severity, 'secondary')
                    
                    section += f"""
                <tr>
                    <td>{i}</td>
                    <td>{vuln.get('header')}</td>
                    <td>{vuln.get('description')}</td>
                    <td><span class="badge badge-{severity_class}">{severity}</span></td>
                    <td>{vuln.get('mitigation')}</td>
                </tr>
"""
                
                section += """
            </tbody>
        </table>
"""
            
            # Insecure Cookies
            if cookie_vulns:
                section += """
        <h3>Insecure Cookies</h3>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Description</th>
                    <th>Severity</th>
                    <th>Mitigation</th>
"""
                
                if self.include_evidence:
                    section += """
                    <th>Evidence</th>
"""
                
                section += """
                </tr>
            </thead>
            <tbody>
"""
                
                for i, vuln in enumerate(cookie_vulns, 1):
                    severity = vuln.get('severity', 'Medium')
                    severity_class = {
                        'High': 'danger',
                        'Medium': 'warning',
                        'Low': 'info'
                    }.get(severity, 'secondary')
                    
                    section += f"""
                <tr>
                    <td>{i}</td>
                    <td>{vuln.get('description')}</td>
                    <td><span class="badge badge-{severity_class}">{severity}</span></td>
                    <td>{vuln.get('mitigation')}</td>
"""
                    
                    if self.include_evidence:
                        section += f"""
                    <td><div class="evidence">{vuln.get('evidence', 'N/A')}</div></td>
"""
                    
                    section += """
                </tr>
"""
                
                section += """
            </tbody>
        </table>
"""
            
            # Information Disclosure
            if info_vulns:
                section += """
        <h3>Information Disclosure</h3>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Header</th>
                    <th>Description</th>
                    <th>Severity</th>
                    <th>Mitigation</th>
"""
                
                if self.include_evidence:
                    section += """
                    <th>Evidence</th>
"""
                
                section += """
                </tr>
            </thead>
            <tbody>
"""
                
                for i, vuln in enumerate(info_vulns, 1):
                    severity = vuln.get('severity', 'Low')
                    severity_class = {
                        'High': 'danger',
                        'Medium': 'warning',
                        'Low': 'info'
                    }.get(severity, 'secondary')
                    
                    section += f"""
                <tr>
                    <td>{i}</td>
                    <td>{vuln.get('header', 'Unknown')}</td>
                    <td>{vuln.get('description')}</td>
                    <td><span class="badge badge-{severity_class}">{severity}</span></td>
                    <td>{vuln.get('mitigation')}</td>
"""
                    
                    if self.include_evidence:
                        section += f"""
                    <td><div class="evidence">{vuln.get('evidence', 'N/A')}</div></td>
"""
                    
                    section += """
                </tr>
"""
                
                section += """
            </tbody>
        </table>
"""
            
            # Default Resources
            if resource_vulns:
                section += """
        <h3>Sensitive Resources</h3>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Description</th>
                    <th>URL</th>
                    <th>Severity</th>
                    <th>Mitigation</th>
                </tr>
            </thead>
            <tbody>
"""
                
                for i, vuln in enumerate(resource_vulns, 1):
                    severity = vuln.get('severity', 'Medium')
                    severity_class = {
                        'High': 'danger',
                        'Medium': 'warning',
                        'Low': 'info'
                    }.get(severity, 'secondary')
                    
                    section += f"""
                <tr>
                    <td>{i}</td>
                    <td>{vuln.get('description')}</td>
                    <td><a href="{vuln.get('url')}" target="_blank">{vuln.get('url')}</a></td>
                    <td><span class="badge badge-{severity_class}">{severity}</span></td>
                    <td>{vuln.get('mitigation')}</td>
                </tr>
"""
                
                section += """
            </tbody>
        </table>
"""
            
            # Other Vulnerabilities
            if other_vulns:
                section += """
        <h3>Other Misconfigurations</h3>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Severity</th>
                    <th>Mitigation</th>
                </tr>
            </thead>
            <tbody>
"""
                
                for i, vuln in enumerate(other_vulns, 1):
                    severity = vuln.get('severity', 'Medium')
                    severity_class = {
                        'High': 'danger',
                        'Medium': 'warning',
                        'Low': 'info'
                    }.get(severity, 'secondary')
                    
                    section += f"""
                <tr>
                    <td>{i}</td>
                    <td>{vuln.get('type')}</td>
                    <td>{vuln.get('description')}</td>
                    <td><span class="badge badge-{severity_class}">{severity}</span></td>
                    <td>{vuln.get('mitigation')}</td>
                </tr>
"""
                
                section += """
            </tbody>
        </table>
"""
            
        else:
            section += """
        <div class="alert alert-success">
            <p>No security misconfigurations detected</p>
        </div>
"""
        
        section += """
    </section>
"""
        return section
    
    def _generate_html_recommendations(self) -> str:
        """Generate remediation recommendations HTML section"""
        section = """
    <section id="recommendations" class="recommendations">
        <h2>Remediation Recommendations</h2>
"""
        
        # XSS Recommendations
        if 'xss' in self.results and self.results['xss']:
            section += """
        <h3>For Cross-Site Scripting (XSS) Vulnerabilities:</h3>
        <ul>
            <li>Implement proper input validation and sanitization</li>
            <li>Use Content-Security-Policy headers</li>
            <li>Apply output encoding when rendering user input</li>
            <li>Consider using frameworks with built-in XSS protection</li>
            <li>Implement HTTPOnly flag for cookies to prevent cookie theft via XSS</li>
        </ul>
"""
        
        # SQLi Recommendations
        if 'sqli' in self.results and self.results['sqli']:
            section += """
        <h3>For SQL Injection Vulnerabilities:</h3>
        <ul>
            <li>Use parameterized queries or prepared statements</li>
            <li>Implement proper input validation and sanitization</li>
            <li>Apply the principle of least privilege for database users</li>
            <li>Consider using ORM frameworks</li>
            <li>Implement database activity monitoring and query logging</li>
        </ul>
"""
        
        # Port Recommendations
        if 'ports' in self.results and self.results['ports']:
            section += """
        <h3>For Open Ports and Services:</h3>
        <ul>
            <li>Close unnecessary ports and services</li>
            <li>Implement proper firewall rules</li>
            <li>Keep services updated to the latest secure versions</li>
            <li>Use network segmentation where possible</li>
            <li>Implement proper authentication for accessible services</li>
        </ul>
"""
        
        # Path Recommendations
        if 'paths' in self.results and self.results['paths']:
            section += """
        <h3>For Vulnerable Paths and Directories:</h3>
        <ul>
            <li>Remove or secure sensitive files from web-accessible directories</li>
            <li>Implement proper access controls and authentication</li>
            <li>Configure web server to deny access to sensitive directories</li>
            <li>Use .htaccess or web.config files to restrict access</li>
            <li>Regular audit and inventory of exposed resources</li>
        </ul>
"""
            
        # Misconfiguration Recommendations
        if 'misconfig' in self.results and self.results['misconfig']:
            section += """
        <h3>For Security Misconfigurations:</h3>
        <ul>
            <li>Implement all recommended security headers</li>
            <li>Ensure cookies have proper security flags (HttpOnly, Secure, SameSite)</li>
            <li>Remove or mask server information disclosure</li>
            <li>Configure error handling to avoid exposing sensitive details</li>
            <li>Disable debug/development modes in production environments</li>
            <li>Regular security configuration reviews and hardening</li>
        </ul>
"""
        
        section += """
    </section>
"""
        return section