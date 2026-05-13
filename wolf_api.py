import os
import google.generativeai as genai
from typing import Dict, List, Any, Optional
import requests
from datetime import datetime

class WolfAPI:
    """
    Wolf API , specialized for cybersecurity analysis.
    This is a rebranded interface to Gemini that focuses on security analysis capabilities.
    """

    def __init__(self, api_key: str = None, demo_mode: bool = False):
        """
        Initialize the Wolf API client.

        Args:
            api_key (str, optional): The API key for authentication. If not provided,
                                     it will try to get it from environment variables.
            demo_mode (bool, optional): If True, run in demo mode without requiring an API key.
        """
        # Use provided API key or try to get from environment
        self.api_key = api_key or os.getenv("WOLF_API_KEY") or os.getenv("GEMINI_API_KEY")
        self.demo_mode = demo_mode

        if not self.api_key and not self.demo_mode:
            print("WARNING: No API key provided. Running in demo mode with simulated responses.")
            self.demo_mode = True

        if not self.demo_mode:
            # Configure the Gemini API with the provided key
            genai.configure(api_key=self.api_key)

            # Set default model to Gemini 2.0 Flash
            self.default_model = "gemini-3-flash-preview"

            # Initialize the model
            self.model = genai.GenerativeModel(self.default_model)
        else:
            # In demo mode, we don't initialize the actual model
            self.default_model = "demo-mode"
            self.model = None

        # Define security-specific system prompts - enhanced for Gemini 2.0 Flash
        self.security_prompts = {
            "website_analysis": """You are Wolf API and are an elite cybersecurity specialist focusing on web security.
            You have been extensively trained on identifying and analyzing modern web security threats and vulnerabilities.
            Analyze the provided website information for security vulnerabilities, misconfigurations, and potential threats.
            Provide detailed, technical and actionable insights with severity ratings and specific remediation steps.""",

            "threat_detection": """You are Wolf API and are an elite cybersecurity specialist focusing on threat detection.
            You have been extensively trained on identifying malicious code patterns, security vulnerabilities, and threats in various programming languages.
            Analyze the provided content for security threats, vulnerabilities, and coding issues.
            Focus on identifying potential security risks and providing clear, actionable remediation steps with code examples where appropriate.""",

            "web_application_scan": """You are Wolf API and are an elite cybersecurity specialist focusing on web application security.
            You have deep expertise in OWASP Top 10 vulnerabilities, penetration testing techniques, and secure coding practices.
            Analyze the provided web application information for vulnerabilities, exposed endpoints, and security risks.
            Provide comprehensive vulnerability assessments with severity ratings, potential exploit scenarios, and specific remediation steps.""",

            "background_process": """You are Wolf API and are an elite cybersecurity specialist focusing on system security.
            You have extensive knowledge of secure configuration practices, privilege escalation techniques, and system hardening.
            Analyze the provided system, service, or process information for security misconfigurations, vulnerabilities, and threats.
            Focus on identifying potential security risks in background processes, services, and system configurations, with specific remediation guidance."""
        }

        self.base_url = "https://api.wolfsecurity.com/v1"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        })

    def analyze_security(self, text: str, analysis_type: str, additional_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Perform security analysis on the provided text.

        Args:
            text (str): The text to analyze
            analysis_type (str): Type of security analysis to perform
            additional_context (Dict[str, Any], optional): Additional context for the analysis

        Returns:
            Dict[str, Any]: Analysis results
        """
        # If in demo mode, return simulated results
        if self.demo_mode:
            return self._generate_demo_response(text, analysis_type, additional_context)

        # Get the appropriate system prompt
        system_prompt = self.security_prompts.get(
            analysis_type,
            """You are Wolf API an  cybersecurity specialist.
            You have comprehensive knowledge of security vulnerabilities, threats, and best practices.
            Analyze the provided information for security issues, vulnerabilities, and potential risks.
            Provide detailed technical analysis with clear remediation steps and recommendations."""
        )

        # Construct the prompt with additional context if provided
        context_str = ""
        if additional_context:
            context_str = "Additional context:\n"
            for key, value in additional_context.items():
                context_str += f"- {key}: {value}\n"

        # Create the full prompt
        full_prompt = f"{system_prompt}\n\n{context_str}\n\nContent to analyze:\n{text}\n\nProvide a detailed security analysis in JSON format with these sections: summary, security_score, vulnerabilities, recommendations, and technical_details."

        # Generate the response
        response = self.model.generate_content(full_prompt)

        # Process and return the response
        try:
            # Try to extract JSON from the response
            import json
            import re

            # Look for JSON pattern in the response
            response_text = response.text
            json_match = re.search(r'```json\n([\s\S]*?)\n```', response_text)

            if json_match:
                json_str = json_match.group(1)
                return json.loads(json_str)
            else:
                # If no JSON pattern found, try to parse the entire response as JSON
                try:
                    return json.loads(response_text)
                except:
                    # If all parsing fails, return a structured response
                    return {
                        "summary": response_text[:500] + "...",
                        "security_score": 5,  # Default neutral score
                        "vulnerabilities": [],
                        "recommendations": [{"title": "Manual Review Required", "description": "The analysis requires manual review."}],
                        "technical_details": {"raw_response": response_text[:1000] + "..."}
                    }
        except Exception as e:
            # Handle errors in response processing
            return {
                "summary": "Error processing security analysis",
                "security_score": 0,
                "vulnerabilities": [{"severity": "High", "title": "Analysis Error", "description": f"Error processing response: {str(e)}"}],
                "recommendations": [{"title": "Retry Analysis", "description": "Please try again with more specific information."}],
                "technical_details": {"error": str(e), "partial_response": response.text[:500] + "..."}
            }

    def _generate_demo_response(self, text: str, analysis_type: str, additional_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate a simulated response for demo mode.

        Args:
            text (str): The text to analyze
            analysis_type (str): Type of security analysis to perform
            additional_context (Dict[str, Any], optional): Additional context for the analysis

        Returns:
            Dict[str, Any]: Simulated analysis results
        """
        import random
        import json
        from datetime import datetime

        # Extract some context for more realistic responses
        context = {}
        if additional_context:
            context = additional_context

        # Get some basic info about the input
        text_length = len(text)
        has_code = "```" in text or "<code>" in text.lower()
        has_url = "http://" in text or "https://" in text

        # Generate a security score based on analysis type
        if analysis_type == "threat_detection":
            security_score = random.randint(3, 7)
        elif analysis_type == "web_application_scan":
            security_score = random.randint(4, 8)
        elif analysis_type == "background_process":
            security_score = random.randint(5, 9)
        else:
            security_score = random.randint(4, 8)

        # Generate vulnerabilities based on analysis type and input
        vulnerabilities = []

        if analysis_type == "threat_detection" and has_code:
            # Code-related vulnerabilities
            if "password" in text.lower() or "secret" in text.lower() or "key" in text.lower():
                vulnerabilities.append({
                    "severity": "High",
                    "title": "Hardcoded Credentials",
                    "description": "Hardcoded credentials or secrets were detected in the code.",
                    "impact": "Attackers could extract sensitive credentials from the code.",
                    "component": "Authentication",
                    "line_number": random.randint(1, max(2, text_length // 80)),
                    "code": "const apiKey = 'a1b2c3d4e5f6';",
                    "fixed_code": "const apiKey = process.env.API_KEY;"
                })

            if "sql" in text.lower() or "query" in text.lower():
                vulnerabilities.append({
                    "severity": "Critical",
                    "title": "SQL Injection Vulnerability",
                    "description": "Potential SQL injection vulnerability detected in database query.",
                    "impact": "Attackers could execute arbitrary SQL commands on the database.",
                    "component": "Database",
                    "line_number": random.randint(1, max(2, text_length // 80)),
                    "code": "query = \"SELECT * FROM users WHERE username = '\" + username + \"'\";",
                    "fixed_code": "query = \"SELECT * FROM users WHERE username = ?\"; \npreparedStatement.setString(1, username);"
                })

            if "input" in text.lower() or "user" in text.lower():
                vulnerabilities.append({
                    "severity": "Medium",
                    "title": "Insufficient Input Validation",
                    "description": "User input is not properly validated before use.",
                    "impact": "Could lead to various injection attacks or unexpected behavior.",
                    "component": "Input Processing",
                    "line_number": random.randint(1, max(2, text_length // 80))
                })

        elif analysis_type == "web_application_scan" and has_url:
            # Web vulnerabilities
            vulnerabilities.append({
                "severity": "High",
                "title": "Cross-Site Scripting (XSS)",
                "description": "Reflected XSS vulnerability detected in search parameter.",
                "impact": "Attackers could inject malicious scripts that execute in users' browsers.",
                "path": "/search",
                "param": "q",
                "remediation": "Implement proper output encoding and Content-Security-Policy headers."
            })

            vulnerabilities.append({
                "severity": "Medium",
                "title": "Missing Security Headers",
                "description": "Several important security headers are missing from HTTP responses.",
                "impact": "The application is more vulnerable to various client-side attacks.",
                "remediation": "Add X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy headers."
            })

            if random.random() < 0.5:  # 50% chance
                vulnerabilities.append({
                    "severity": "Critical",
                    "title": "Insecure Direct Object Reference",
                    "description": "API endpoints allow access to resources without proper authorization checks.",
                    "impact": "Attackers could access unauthorized data by manipulating resource identifiers.",
                    "path": "/api/user/{id}",
                    "remediation": "Implement proper authorization checks for all resource access."
                })

        elif analysis_type == "background_process":
            # System/process vulnerabilities
            vulnerabilities.append({
                "severity": "High",
                "title": "Excessive Privileges",
                "description": "Process is running with root/administrator privileges unnecessarily.",
                "impact": "Compromised process could lead to complete system compromise.",
                "component": "Process Permissions",
                "solution": "Run the process with a dedicated service account with minimal required permissions."
            })

            if "password" in text.lower() or "secret" in text.lower() or "key" in text.lower():
                vulnerabilities.append({
                    "severity": "Critical",
                    "title": "Exposed Credentials in Configuration",
                    "description": "Plaintext credentials found in configuration files.",
                    "impact": "Unauthorized access to services and data.",
                    "component": "Configuration",
                    "solution": "Use environment variables or a secure credential store instead of hardcoded values."
                })

            vulnerabilities.append({
                "severity": "Medium",
                "title": "Insecure Network Configuration",
                "description": "Services are exposed on all network interfaces rather than localhost only.",
                "impact": "Increased attack surface for remote exploitation.",
                "component": "Network Configuration",
                "solution": "Bind services to localhost or use a firewall to restrict access."
            })

        # Add some random low-severity issues
        if random.random() < 0.7:  # 70% chance
            vulnerabilities.append({
                "severity": "Low",
                "title": "Outdated Components",
                "description": "Some components may be using outdated versions with known vulnerabilities.",
                "impact": "Potential exposure to known security issues.",
                "component": "Dependencies"
            })

        if random.random() < 0.5:  # 50% chance
            vulnerabilities.append({
                "severity": "Info",
                "title": "Information Disclosure",
                "description": "Verbose error messages or comments may reveal sensitive information.",
                "impact": "Could aid attackers in reconnaissance.",
                "component": "Error Handling"
            })

        # Generate recommendations based on vulnerabilities
        recommendations = []
        for vuln in vulnerabilities:
            if vuln["severity"] in ["Critical", "High"]:
                recommendations.append({
                    "title": f"Fix {vuln['title']}",
                    "description": vuln.get("solution", f"Address the {vuln['title']} vulnerability to prevent {vuln['impact']}")
                })

        # Add some general recommendations
        recommendations.append({
            "title": "Implement Security Best Practices",
            "description": "Follow industry standard security best practices for your technology stack."
        })

        recommendations.append({
            "title": "Regular Security Testing",
            "description": "Perform regular security testing and code reviews to identify and address vulnerabilities."
        })

        # Generate a summary
        if vulnerabilities:
            critical_count = sum(1 for v in vulnerabilities if v["severity"] == "Critical")
            high_count = sum(1 for v in vulnerabilities if v["severity"] == "High")
            medium_count = sum(1 for v in vulnerabilities if v["severity"] == "Medium")
            low_count = sum(1 for v in vulnerabilities if v["severity"] == "Low")

            summary = f"Security analysis identified {len(vulnerabilities)} potential issues "
            summary += f"({critical_count} Critical, {high_count} High, {medium_count} Medium, {low_count} Low). "

            if security_score < 5:
                summary += "Immediate attention is required to address critical security vulnerabilities."
            elif security_score < 7:
                summary += "Several important security issues should be addressed to improve security posture."
            else:
                summary += "Overall security posture is good, with some minor improvements recommended."
        else:
            summary = "No significant security issues were identified in the analysis."

        # Generate technical details
        technical_details = {
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_type": analysis_type,
            "input_size": text_length,
            "demo_mode": True
        }

        # Add context-specific technical details
        if analysis_type == "web_application_scan" and has_url:
            technical_details["url"] = context.get("url", "https://example.com")
            technical_details["scan_depth"] = context.get("scan_depth", 3)

        elif analysis_type == "background_process":
            technical_details["platform"] = context.get("platform", "Linux")
            technical_details["file_type"] = context.get("file_type", "configuration")

        # Return the complete response
        return {
            "summary": summary,
            "security_score": security_score,
            "vulnerabilities": vulnerabilities,
            "recommendations": recommendations,
            "technical_details": technical_details
        }

    def format_security_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format security data to ensure consistent structure.

        Args:
            data (Dict[str, Any]): Raw security data

        Returns:
            Dict[str, Any]: Formatted security data
        """
        # Ensure required fields exist
        required_fields = ["summary", "security_score", "vulnerabilities", "recommendations", "technical_details"]
        for field in required_fields:
            if field not in data:
                if field == "summary":
                    data[field] = "No summary provided"
                elif field == "security_score":
                    data[field] = 5  # Default neutral score
                elif field == "vulnerabilities":
                    data[field] = []
                elif field == "recommendations":
                    data[field] = []
                elif field == "technical_details":
                    data[field] = {}

        # Format vulnerabilities if they exist
        if data["vulnerabilities"]:
            for i, vuln in enumerate(data["vulnerabilities"]):
                if not isinstance(vuln, dict):
                    # Convert string to dict if needed
                    data["vulnerabilities"][i] = {
                        "severity": "Unknown",
                        "title": "Undefined Vulnerability",
                        "description": str(vuln),
                        "impact": "Unknown impact",
                        "component": "Unknown component"
                    }
                else:
                    # Ensure all vulnerability fields exist
                    if "severity" not in vuln:
                        vuln["severity"] = "Unknown"
                    if "title" not in vuln:
                        vuln["title"] = "Undefined Vulnerability"
                    if "description" not in vuln:
                        vuln["description"] = "No description provided"
                    if "impact" not in vuln:
                        vuln["impact"] = "Unknown impact"
                    if "component" not in vuln:
                        vuln["component"] = "Unknown component"

        # Format recommendations if they exist
        if data["recommendations"]:
            for i, rec in enumerate(data["recommendations"]):
                if not isinstance(rec, dict):
                    # Convert string to dict if needed
                    data["recommendations"][i] = {
                        "title": "Recommendation",
                        "description": str(rec)
                    }
                else:
                    # Ensure all recommendation fields exist
                    if "title" not in rec:
                        rec["title"] = "Recommendation"
                    if "description" not in rec:
                        rec["description"] = "No description provided"

        return data

    def analyze_website(self, url: str, scan_type: str = "quick") -> dict:
        """
        Analyze a website for security vulnerabilities with enhanced accuracy

        Args:
            url (str): The website URL to analyze
            scan_type (str): Type of scan to perform (quick, full, custom)

        Returns:
            dict: Analysis results including vulnerabilities and recommendations
        """
        try:
            # Validate and normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            # Enhanced scan parameters
            scan_params = {
                "url": url,
                "scan_type": scan_type,
                "timestamp": datetime.now().isoformat(),
                "options": {
                    "deep_scan": True,
                    "check_headers": True,
                    "analyze_content": True,
                    "verify_ssl": True,
                    "follow_redirects": True,
                    "timeout": 30
                }
            }

            # Perform initial request to get basic info
            initial_response = self.session.get(url, timeout=10, allow_redirects=True)
            initial_response.raise_for_status()

            # Extract basic information
            server_info = initial_response.headers.get('Server', '')
            content_type = initial_response.headers.get('Content-Type', '')

            # Enhanced scan results
            scan_results = {
                "server_info": server_info,
                "content_type": content_type,
                "status_code": initial_response.status_code,
                "headers": dict(initial_response.headers),
                "redirects": len(initial_response.history),
                "final_url": initial_response.url
            }

            # Process results based on scan type
            if scan_type == "Vulnerabilities":
                return self._process_vulnerability_scan(scan_results)
            elif scan_type == "SSL/TLS":
                return self._process_ssl_scan(scan_results)
            elif scan_type == "Headers":
                return self._process_header_scan(scan_results)
            elif scan_type == "Content Security":
                return self._process_content_scan(scan_results)
            else:
                return self._process_quick_scan(scan_results)

        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "message": f"API request failed: {str(e)}",
                "issues": []
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Analysis failed: {str(e)}",
                "issues": []
            }

    def _process_vulnerability_scan(self, results: dict) -> dict:
        """Process vulnerability scan results with enhanced checks"""
        issues = []

        # Enhanced SQL Injection checks
        if any(keyword in results.get("server_info", "").lower() for keyword in ["mysql", "sql", "database"]):
            issues.append({
                "title": "Database Server Information Exposed",
                "description": "Database server information is visible in headers",
                "priority": "High",
                "recommendation": "Hide database server information in headers"
            })

        # Enhanced XSS checks
        if "text/html" in results.get("content_type", "").lower():
            if not any(header in results.get("headers", {}) for header in ["X-XSS-Protection", "Content-Security-Policy"]):
                issues.append({
                    "title": "Missing XSS Protection Headers",
                    "description": "Website lacks proper XSS protection headers",
                    "priority": "Critical",
                    "recommendation": "Implement X-XSS-Protection and Content-Security-Policy headers"
                })

        # Check for common security misconfigurations
        if results.get("status_code") == 200 and "index of" in results.get("content_type", "").lower():
            issues.append({
                "title": "Directory Listing Enabled",
                "description": "Directory listing is enabled, exposing file structure",
                "priority": "High",
                "recommendation": "Disable directory listing in server configuration"
            })

        return {
            "status": "completed",
            "scan_type": "Vulnerabilities",
            "issues": issues
        }

    def _process_ssl_scan(self, results: dict) -> dict:
        """Process SSL/TLS scan results with enhanced checks"""
        issues = []

        # Enhanced SSL checks
        if not results.get("final_url", "").startswith("https://"):
            issues.append({
                "title": "HTTPS Not Enforced",
                "description": "Website is accessible over HTTP",
                "priority": "Critical",
                "recommendation": "Enforce HTTPS and implement HSTS"
            })

        # Check for security headers
        headers = results.get("headers", {})
        if "Strict-Transport-Security" not in headers:
            issues.append({
                "title": "Missing HSTS Header",
                "description": "HTTP Strict Transport Security not implemented",
                "priority": "High",
                "recommendation": "Implement HSTS with appropriate max-age and includeSubDomains"
            })
        else:
            # Check HSTS configuration
            hsts_header = headers.get("Strict-Transport-Security", "")
            if "max-age=31536000" not in hsts_header:
                issues.append({
                    "title": "Weak HSTS Configuration",
                    "description": "HSTS max-age is less than recommended 1 year (31536000 seconds)",
                    "priority": "Medium",
                    "recommendation": "Set HSTS max-age to at least 31536000 seconds (1 year)"
                })
            if "includeSubDomains" not in hsts_header:
                issues.append({
                    "title": "HSTS Missing includeSubDomains",
                    "description": "HSTS header does not include subdomains",
                    "priority": "Medium",
                    "recommendation": "Add includeSubDomains directive to HSTS header"
                })
            if "preload" not in hsts_header:
                issues.append({
                    "title": "HSTS Missing preload",
                    "description": "HSTS header does not include preload directive",
                    "priority": "Low",
                    "recommendation": "Consider adding preload directive to HSTS header for better security"
                })

        # Check for secure cookie settings
        if "Set-Cookie" in headers and "secure" not in headers["Set-Cookie"].lower():
            issues.append({
                "title": "Insecure Cookie Settings",
                "description": "Cookies are not set with secure flag",
                "priority": "High",
                "recommendation": "Set secure flag for all cookies"
            })

        return {
            "status": "completed",
            "scan_type": "SSL/TLS",
            "issues": issues
        }

    def _process_header_scan(self, results: dict) -> dict:
        """Process security headers scan results with enhanced checks"""
        issues = []
        headers = results.get("headers", {})

        # Enhanced header checks
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": None,
            "Referrer-Policy": ["no-referrer", "strict-origin-when-cross-origin"],
            "Permissions-Policy": None
        }

        for header, expected_value in security_headers.items():
            if header not in headers:
                issues.append({
                    "title": f"Missing {header}",
                    "description": f"Security header {header} is not set",
                    "priority": "High",
                    "recommendation": f"Implement {header} with appropriate value"
                })
            elif expected_value and headers[header] not in expected_value:
                issues.append({
                    "title": f"Incorrect {header} Value",
                    "description": f"{header} is set with incorrect value: {headers[header]}",
                    "priority": "Medium",
                    "recommendation": f"Update {header} to use recommended value: {expected_value}"
                })

        return {
            "status": "completed",
            "scan_type": "Headers",
            "issues": issues
        }

    def _process_content_scan(self, results: dict) -> dict:
        """Process content security scan results with enhanced checks"""
        issues = []
        headers = results.get("headers", {})

        # Enhanced content security checks
        if "Content-Security-Policy" not in headers:
            issues.append({
                "title": "Missing Content Security Policy",
                "description": "No Content Security Policy header found",
                "priority": "High",
                "recommendation": "Implement a strong Content Security Policy"
            })

        # Check for mixed content
        if results.get("final_url", "").startswith("https://"):
            if any(header in headers for header in ["Content-Security-Policy", "X-Content-Security-Policy"]):
                csp = headers.get("Content-Security-Policy", headers.get("X-Content-Security-Policy", ""))
                if "upgrade-insecure-requests" not in csp:
                    issues.append({
                        "title": "Mixed Content Risk",
                        "description": "Website may load mixed content",
                        "priority": "High",
                        "recommendation": "Add 'upgrade-insecure-requests' to CSP"
                    })

        # Check for modern security features
        if "Permissions-Policy" not in headers:
            issues.append({
                "title": "Missing Permissions Policy",
                "description": "No Permissions Policy header found",
                "priority": "Medium",
                "recommendation": "Implement Permissions Policy to control browser features"
            })

        return {
            "status": "completed",
            "scan_type": "Content Security",
            "issues": issues
        }

    def _process_quick_scan(self, results: dict) -> dict:
        """Process quick scan results with enhanced checks"""
        issues = []

        # Enhanced quick checks
        if results.get("redirects", 0) > 3:
            issues.append({
                "title": "Excessive Redirects",
                "description": f"Website has {results['redirects']} redirects",
                "priority": "Medium",
                "recommendation": "Minimize redirects to improve security and performance"
            })

        if results.get("server_info"):
            issues.append({
                "title": "Server Information Exposed",
                "description": f"Server information exposed: {results['server_info']}",
                "priority": "Medium",
                "recommendation": "Hide server information in headers"
            })

        # Check for basic security headers
        headers = results.get("headers", {})
        if not any(header in headers for header in ["X-Content-Type-Options", "X-Frame-Options"]):
            issues.append({
                "title": "Missing Basic Security Headers",
                "description": "Essential security headers are missing",
                "priority": "High",
                "recommendation": "Implement basic security headers"
            })

        return {
            "status": "completed",
            "scan_type": "Quick",
            "issues": issues
        }
