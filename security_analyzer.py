import streamlit as st
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import json
import re

def analyze_website(api_client, url: str) -> Dict[str, Any]:
    """
    Analyze a website for security vulnerabilities.

    Args:
        api_client: The Wolf API client
        url (str): The URL to analyze

    Returns:
        Dict[str, Any]: Analysis results
    """
    # Validate URL
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError("Invalid URL format")
    except Exception as e:
        raise ValueError(f"Invalid URL: {str(e)}")

    # We would typically do an actual request to the website here,
    # but for this application we'll simulate getting website data
    # and have the LLM analyze the URL itself

    # Gather basic information about the website
    context = {
        "url": url,
        "analysis_type": "website security assessment",
        "analyze_headers": True,
        "analyze_ssl": True,
        "analyze_content_security": True
    }

    # Create analysis request
    analysis_text = f"""
    Perform a comprehensive security analysis of the website: {url}

    Focus on:
    1. Common web security vulnerabilities
    2. SSL/TLS configuration
    3. HTTP security headers
    4. Content security policy
    5. Authentication and authorization issues
    6. Input validation and sanitization
    7. Data protection measures

    The URL structure, domain name, and TLD may provide hints about the website's purpose and potential security concerns.
    """

    # Send to Wolf API for analysis
    result = api_client.analyze_security(analysis_text, "website_analysis", context)

    # Format the response
    formatted_result = api_client.format_security_data(result)

    return formatted_result

def analyze_threats(api_client, content: str, input_type: str, language: str, analysis_type: str = None) -> Dict[str, Any]:
    """
    Analyze content for security threats.

    Args:
        api_client: The Wolf API client
        content (str): The content to analyze
        input_type (str): Type of input content
        language (str): Programming language (if applicable)
        analysis_type (str, optional): Type of analysis to perform (syntax, vulnerability, security)

    Returns:
        Dict[str, Any]: Analysis results
    """
    # Set up context for analysis
    context = {
        "input_type": input_type,
        "language": language,
        "analysis_type": analysis_type or "security threat detection"
    }

    # Create analysis request
    analysis_text = f"""
    Perform a comprehensive security threat analysis of the following content:

    Content Type: {input_type}
    Language: {language}
    Analysis Type: {analysis_type or "comprehensive"}

    Content:
    ```
    {content}
    ```

    Focus on identifying:
    1. Security vulnerabilities
    2. Potential attack vectors
    3. Coding flaws with security implications
    4. Suspicious patterns
    5. Implementation weaknesses
    6. Risk assessment

    {"Focus specifically on syntax and code structure issues." if analysis_type == "syntax" else ""}
    {"Focus specifically on security vulnerabilities and exploits." if analysis_type == "vulnerability" else ""}
    {"Focus specifically on overall security posture and risk assessment." if analysis_type == "security" else ""}
    """

    # Send to Wolf API for analysis
    result = api_client.analyze_security(analysis_text, "threat_detection", context)

    # For threat analysis, we need a specific format
    if "threats" not in result:
        # Convert vulnerabilities to threats if needed
        result["threats"] = result.get("vulnerabilities", [])

    # Ensure we have a summary
    if "summary" not in result or not result["summary"]:
        result["summary"] = "Analysis completed. See detailed results below."

    return result

def scan_web_application(api_client, url: str, auth_params: Dict[str, Any], scan_params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simulate a web application security scan.

    Args:
        api_client: The Wolf API client
        url (str): The URL to scan
        auth_params (Dict[str, Any]): Authentication parameters
        scan_params (Dict[str, Any]): Scan configuration parameters

    Returns:
        Dict[str, Any]: Scan results
    """
    # Validate URL
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError("Invalid URL format")
    except Exception as e:
        raise ValueError(f"Invalid URL: {str(e)}")

    # Set up context for analysis
    context = {
        "url": url,
        "auth_params": json.dumps(auth_params),
        "scan_params": json.dumps(scan_params),
        "scan_depth": scan_params.get("depth", 3),
        "scan_options": ", ".join(scan_params.get("options", [])),
        "analysis_type": "web application security scan"
    }

    # Create analysis request
    analysis_text = f"""
    Perform a comprehensive web application security scan for: {url}

    Scan Configuration:
    - Depth: {scan_params.get('depth', 3)} (1-5 scale)
    - Target Options: {', '.join(scan_params.get('options', []))}
    - Excluded Paths: {', '.join(scan_params.get('exclude_paths', []))}

    Authentication Configuration:
    {json.dumps(auth_params, indent=2) if auth_params else "No authentication"}

    Simulate a thorough application security assessment focusing on:
    1. Input validation vulnerabilities (XSS, SQL Injection, etc.)
    2. Authentication and session management
    3. Access control issues
    4. Security misconfigurations
    5. Sensitive data exposure
    6. API security issues
    7. Client-side vulnerabilities

    Provide a detailed analysis with the following information:
    - Summary of findings
    - Discovered vulnerabilities with severity ratings
    - Site map of detected endpoints
    - Statistics about the scan
    - Technical details and recommendations
    """

    # Send to Wolf API for analysis
    result = api_client.analyze_security(analysis_text, "web_application_scan", context)

    # Format the response with web scan specific fields
    if "stats" not in result:
        result["stats"] = {
            "pages_scanned": scan_params.get("depth", 3) * 5,  # Simulate page count based on depth
            "total_vulnerabilities": len(result.get("vulnerabilities", [])),
            "high_risk": sum(1 for v in result.get("vulnerabilities", []) if isinstance(v, dict) and v.get("severity") == "High"),
            "duration": scan_params.get("depth", 3) * 12  # Simulate scan duration
        }

    if "site_map" not in result:
        # Generate a simulated site map
        result["site_map"] = generate_sitemap(url, scan_params.get("depth", 3))

    return result

def analyze_background_processes(api_client, content: str, analysis_type: str, platform: str, file_type: str) -> Dict[str, Any]:
    """
    Analyze background processes and configurations for security issues.

    Args:
        api_client: The Wolf API client
        content (str): The configuration or process data to analyze
        analysis_type (str): Type of analysis to perform
        platform (str): Target platform
        file_type (str): Type of input file/data

    Returns:
        Dict[str, Any]: Analysis results
    """
    # Set up context for analysis
    context = {
        "analysis_type": analysis_type,
        "platform": platform,
        "file_type": file_type
    }

    # Create analysis request
    analysis_text = f"""
    Perform a comprehensive security analysis of the following {platform} {file_type}:

    Analysis Type: {analysis_type}
    Platform: {platform}
    File Type: {file_type}

    Content:
    ```
    {content}
    ```

    Focus on identifying:
    1. Security misconfigurations
    2. Insecure default settings
    3. Unnecessary exposed services or ports
    4. Privilege issues and escalation risks
    5. Insecure authentication mechanisms
    6. Outdated or vulnerable components
    7. Suspicious processes or potential backdoors

    Provide a detailed analysis with actionable recommendations.
    Include specific configuration improvements where possible.
    """

    # Send to Wolf API for analysis
    result = api_client.analyze_security(analysis_text, "background_process", context)

    # Ensure we have the right format for background process analysis
    if "configuration_analysis" not in result:
        result["configuration_analysis"] = {}

        # Create some sections based on the analysis type
        if analysis_type == "System Configuration":
            result["configuration_analysis"]["System Settings"] = []
            result["configuration_analysis"]["User Permissions"] = []
            result["configuration_analysis"]["Network Configuration"] = []
        elif analysis_type == "Service Configuration":
            result["configuration_analysis"]["Service Settings"] = []
            result["configuration_analysis"]["Security Mechanisms"] = []
            result["configuration_analysis"]["Authentication"] = []
        elif analysis_type == "Process Log Analysis":
            result["configuration_analysis"]["Process Activity"] = []
            result["configuration_analysis"]["Suspicious Events"] = []
            result["configuration_analysis"]["Error Patterns"] = []
        elif analysis_type == "Network Service Analysis":
            result["configuration_analysis"]["Open Ports"] = []
            result["configuration_analysis"]["Service Configurations"] = []
            result["configuration_analysis"]["Network Protocols"] = []

        # Convert vulnerabilities to configuration items if needed
        for vuln in result.get("vulnerabilities", []):
            if isinstance(vuln, dict):
                section = "System Settings"  # Default section

                # Try to determine the appropriate section
                if "user" in vuln.get("component", "").lower() or "permission" in vuln.get("component", "").lower():
                    section = "User Permissions"
                elif "network" in vuln.get("component", "").lower() or "port" in vuln.get("component", "").lower():
                    section = "Network Configuration" if analysis_type == "System Configuration" else "Open Ports"
                elif "service" in vuln.get("component", "").lower():
                    section = "Service Settings" if analysis_type == "Service Configuration" else "Service Configurations"
                elif "auth" in vuln.get("component", "").lower():
                    section = "Authentication"
                elif "process" in vuln.get("component", "").lower() or "activity" in vuln.get("component", "").lower():
                    section = "Process Activity"
                elif "error" in vuln.get("component", "").lower():
                    section = "Error Patterns"

                # Create the configuration item
                config_item = {
                    "status": "error" if vuln.get("severity") == "High" else "warning",
                    "message": f"{vuln.get('title')}: {vuln.get('description')}"
                }

                # Add to the appropriate section if it exists
                if section in result["configuration_analysis"]:
                    result["configuration_analysis"][section].append(config_item)
                else:
                    # If section doesn't exist, create it
                    result["configuration_analysis"][section] = [config_item]

    # Ensure we have security issues
    if "issues" not in result:
        result["issues"] = []

        # Convert from vulnerabilities if needed
        for vuln in result.get("vulnerabilities", []):
            if isinstance(vuln, dict):
                issue = {
                    "title": vuln.get("title", "Unnamed Issue"),  # Ensure title is always present
                    "description": vuln.get("description", "No description provided"),
                    "severity": vuln.get("severity", "Medium"),
                    "affected_component": vuln.get("component", "Unknown"),
                    "risk": vuln.get("impact", "No risk information provided"),
                    "solution": vuln.get("solution", "No solution provided")
                }

                # Additional fields if available
                if "line_number" in vuln:
                    issue["line_number"] = vuln["line_number"]
                if "code" in vuln:
                    issue["current_code"] = vuln["code"]
                if "fixed_code" in vuln:
                    issue["suggested_code"] = vuln["fixed_code"]

                result["issues"].append(issue)

    # Ensure we have recommendations
    if "recommendations" not in result:
        result["recommendations"] = []

        # Generate some recommendations if none exist
        if not result["recommendations"]:
            for issue in result.get("issues", []):
                # Only add recommendations from High and Critical issues to avoid duplication
                if issue.get("severity") in ["Critical", "High"]:
                    rec = {
                        "title": f"Address {issue.get('severity')} Issue: {issue.get('title')}",
                        "description": f"Implement recommended solution: {issue.get('solution', 'Review and update configuration')}"
                    }
                    result["recommendations"].append(rec)

            # Add general recommendations if we don't have any yet
            if not result["recommendations"]:
                result["recommendations"] = [
                    {
                        "title": "Review Security Best Practices",
                        "description": "Regularly review and apply security best practices for your platform and configuration type."
                    },
                    {
                        "title": "Implement Least Privilege Principle",
                        "description": "Ensure all processes and services run with the minimum required privileges."
                    },
                    {
                        "title": "Regular Security Audits",
                        "description": "Perform regular security audits and update configurations based on findings."
                    }
                ]

    # Ensure we have a security score
    if "security_score" not in result:
        # Calculate a score based on issues
        issues = result.get("issues", [])
        if not issues:
            result["security_score"] = 10  # Perfect score if no issues
        else:
            # Calculate score based on severity of issues
            severity_weights = {
                "Critical": 2.5,
                "High": 2.0,
                "Medium": 1.0,
                "Low": 0.5,
                "Info": 0.1
            }

            total_weight = sum(severity_weights.get(issue.get("severity", "Medium"), 1.0) for issue in issues)
            max_penalty = min(10, total_weight)  # Cap at 10

            result["security_score"] = max(0, round(10 - max_penalty, 1))  # Ensure score is at least 0

    # Ensure we have a summary
    if "summary" not in result:
        issue_count = len(result.get("issues", []))
        if issue_count == 0:
            result["summary"] = f"No security issues were identified in the {analysis_type.lower()} for {platform}. The configuration appears to follow security best practices."
        else:
            # Count issues by severity
            severity_counts = {}
            for issue in result.get("issues", []):
                severity = issue.get("severity", "Medium")
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts[severity] = 1

            # Create summary
            severity_summary = ", ".join([f"{count} {severity}" for severity, count in severity_counts.items()])
            score = result["security_score"]

            result["summary"] = f"Analysis of {analysis_type.lower()} for {platform} identified {issue_count} security issues ({severity_summary}). Overall security score: {score}/10. Review the identified issues and implement the recommended solutions to improve security posture."

    # Ensure we have technical details
    if "technical_details" not in result:
        result["technical_details"] = {
            "analysis_type": analysis_type,
            "platform": platform,
            "file_type": file_type,
            "issue_count": len(result.get("issues", [])),
            "configuration_sections": list(result.get("configuration_analysis", {}).keys()),
            "security_score": result.get("security_score", 0)
        }

    return result

def merge_threat_results(results_list) -> Dict[str, Any]:
    """
    Merge results from different threat analysis tasks.

    Args:
        results_list: List of result dictionaries from different analysis tasks

    Returns:
        Dict[str, Any]: Merged analysis results
    """
    # Initialize the merged result
    merged_result = {
        "summary": "",
        "threats": [],
        "recommendations": []
    }

    # Process each result
    for result in results_list:
        # Merge threats
        if "threats" in result:
            merged_result["threats"].extend(result["threats"])
        elif "vulnerabilities" in result:
            # Some results might use "vulnerabilities" instead of "threats"
            merged_result["threats"].extend(result["vulnerabilities"])

        # Merge recommendations
        if "recommendations" in result:
            merged_result["recommendations"].extend(result["recommendations"])

        # Append to summary
        if "summary" in result and result["summary"]:
            if merged_result["summary"]:
                merged_result["summary"] += "\n\n" + result["summary"]
            else:
                merged_result["summary"] = result["summary"]

    # Remove duplicate threats and recommendations
    unique_threats = []
    threat_titles = set()
    for threat in merged_result["threats"]:
        if isinstance(threat, dict) and "title" in threat:
            if threat["title"] not in threat_titles:
                threat_titles.add(threat["title"])
                unique_threats.append(threat)
        else:
            unique_threats.append(threat)

    unique_recommendations = []
    rec_titles = set()
    for rec in merged_result["recommendations"]:
        if isinstance(rec, dict) and "title" in rec:
            if rec["title"] not in rec_titles:
                rec_titles.add(rec["title"])
                unique_recommendations.append(rec)
        elif isinstance(rec, str) and rec not in rec_titles:
            rec_titles.add(rec)
            unique_recommendations.append(rec)

    merged_result["threats"] = unique_threats
    merged_result["recommendations"] = unique_recommendations

    # If no summary was generated, create one
    if not merged_result["summary"]:
        threat_count = len(merged_result["threats"])
        if threat_count == 0:
            merged_result["summary"] = "No security threats were detected in the analysis."
        else:
            severity_counts = {}
            for threat in merged_result["threats"]:
                if isinstance(threat, dict) and "severity" in threat:
                    severity = threat["severity"]
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

            severity_summary = ", ".join([f"{count} {severity}" for severity, count in severity_counts.items()])
            merged_result["summary"] = f"Analysis detected {threat_count} potential security issues ({severity_summary}). Review the detailed findings below."

    return merged_result

def merge_process_analysis_results(analysis_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Merge results from different background process analysis types.

    Args:
        analysis_results: Dictionary of analysis results by type

    Returns:
        Dict[str, Any]: Merged analysis results
    """
    # Initialize the merged result
    merged_result = {
        "summary": "",
        "issues": [],
        "recommendations": [],
        "configuration_analysis": {},
        "security_score": 0,
        "technical_details": {}
    }

    # Process each analysis result
    total_score = 0
    score_count = 0

    for analysis_type, result in analysis_results.items():
        # Merge issues
        if "issues" in result:
            merged_result["issues"].extend(result["issues"])

        # Merge recommendations
        if "recommendations" in result:
            merged_result["recommendations"].extend(result["recommendations"])

        # Merge configuration analysis sections
        if "configuration_analysis" in result:
            for section, items in result["configuration_analysis"].items():
                if section not in merged_result["configuration_analysis"]:
                    merged_result["configuration_analysis"][section] = items
                else:
                    merged_result["configuration_analysis"][section].extend(items)

        # Aggregate security score
        if "security_score" in result:
            total_score += result["security_score"]
            score_count += 1

        # Merge technical details
        if "technical_details" in result:
            merged_result["technical_details"][analysis_type] = result["technical_details"]

        # Append to summary
        if "summary" in result and result["summary"]:
            if merged_result["summary"]:
                merged_result["summary"] += "\n\n" + result["summary"]
            else:
                merged_result["summary"] = result["summary"]

    # Calculate average security score
    if score_count > 0:
        merged_result["security_score"] = round(total_score / score_count, 1)
    else:
        merged_result["security_score"] = 5.0  # Default score

    # Remove duplicate issues and recommendations
    unique_issues = []
    issue_titles = set()
    for issue in merged_result["issues"]:
        if isinstance(issue, dict) and "title" in issue:
            if issue["title"] not in issue_titles:
                issue_titles.add(issue["title"])
                unique_issues.append(issue)
        else:
            unique_issues.append(issue)

    unique_recommendations = []
    rec_titles = set()
    for rec in merged_result["recommendations"]:
        if isinstance(rec, dict) and "title" in rec:
            if rec["title"] not in rec_titles:
                rec_titles.add(rec["title"])
                unique_recommendations.append(rec)
        elif isinstance(rec, str) and rec not in rec_titles:
            rec_titles.add(rec)
            unique_recommendations.append(rec)

    merged_result["issues"] = unique_issues
    merged_result["recommendations"] = unique_recommendations

    # Generate a comprehensive summary if none exists
    if not merged_result["summary"]:
        issue_count = len(merged_result["issues"])
        if issue_count == 0:
            merged_result["summary"] = "No security issues were identified in the analysis. The configuration appears to follow security best practices."
        else:
            # Count issues by severity
            severity_counts = {}
            for issue in merged_result["issues"]:
                severity = issue.get("severity", "Medium")
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts[severity] = 1

            # Create summary
            severity_summary = ", ".join([f"{count} {severity}" for severity, count in severity_counts.items()])
            score = merged_result["security_score"]

            merged_result["summary"] = f"Analysis identified {issue_count} security issues ({severity_summary}). Overall security score: {score}/10. Review the identified issues and implement the recommended solutions to improve security posture."

    return merged_result


def merge_scan_results(scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Merge results from different scan types.

    Args:
        scan_results: List of scan result dictionaries

    Returns:
        Dict[str, Any]: Merged scan results
    """
    # Initialize the merged result
    merged_result = {
        "summary": "",
        "vulnerabilities": [],
        "site_map": [],
        "stats": {
            "pages_scanned": 0,
            "total_vulnerabilities": 0,
            "high_risk": 0,
            "duration": 0
        },
        "technical_details": {}
    }

    # Process each scan result
    for result in scan_results:
        # Merge vulnerabilities
        if "vulnerabilities" in result:
            merged_result["vulnerabilities"].extend(result["vulnerabilities"])

        # Merge site map (avoid duplicates)
        if "site_map" in result:
            existing_paths = set()

            # Create a set of existing paths
            for item in merged_result["site_map"]:
                if isinstance(item, dict) and "method" in item and "path" in item:
                    path_key = f"{item['method']}:{item['path']}"
                    existing_paths.add(path_key)

            # Add new items if they don't exist yet
            for item in result["site_map"]:
                if isinstance(item, dict) and "method" in item and "path" in item:
                    path_key = f"{item['method']}:{item['path']}"
                    if path_key not in existing_paths:
                        # Ensure the item has all required fields
                        if "params" not in item:
                            item["params"] = []
                        merged_result["site_map"].append(item)
                        existing_paths.add(path_key)

        # Aggregate stats
        if "stats" in result:
            merged_result["stats"]["pages_scanned"] += result["stats"].get("pages_scanned", 0)
            merged_result["stats"]["total_vulnerabilities"] += result["stats"].get("total_vulnerabilities", 0)
            merged_result["stats"]["high_risk"] += result["stats"].get("high_risk", 0)
            merged_result["stats"]["duration"] += result["stats"].get("duration", 0)

        # Merge technical details
        if "technical_details" in result:
            for key, value in result["technical_details"].items():
                if key not in merged_result["technical_details"]:
                    merged_result["technical_details"][key] = value
                elif isinstance(value, list) and isinstance(merged_result["technical_details"][key], list):
                    merged_result["technical_details"][key].extend(value)
                elif isinstance(value, dict) and isinstance(merged_result["technical_details"][key], dict):
                    merged_result["technical_details"][key].update(value)

        # Append to summary
        if "summary" in result and result["summary"]:
            if merged_result["summary"]:
                merged_result["summary"] += "\n\n" + result["summary"]
            else:
                merged_result["summary"] = result["summary"]

    # Generate a comprehensive summary if none exists
    if not merged_result["summary"]:
        vuln_count = len(merged_result["vulnerabilities"])
        if vuln_count == 0:
            merged_result["summary"] = "No vulnerabilities were detected in the scan."
        else:
            severity_counts = {}
            for vuln in merged_result["vulnerabilities"]:
                if isinstance(vuln, dict) and "severity" in vuln:
                    severity = vuln["severity"]
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

            severity_summary = ", ".join([f"{count} {severity}" for severity, count in severity_counts.items()])
            merged_result["summary"] = f"Scan detected {vuln_count} vulnerabilities ({severity_summary}) across {merged_result['stats']['pages_scanned']} pages. Review the detailed findings below."

    return merged_result

# This function was a duplicate and has been removed to avoid confusion.
# The first implementation of merge_process_analysis_results (lines 499-608) is used instead.

def generate_sitemap(url: str, depth: int) -> List[Dict[str, Any]]:
    """
    Generate a simulated site map for a web application.

    Args:
        url (str): The base URL
        depth (int): Scan depth

    Returns:
        List[Dict[str, Any]]: Simulated site map
    """
    # Parse the URL to get the base
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

    # Common web application paths for simulation
    common_paths = [
        {"method": "GET", "path": "/", "params": []},
        {"method": "GET", "path": "/login", "params": ["username", "password"]},
        {"method": "POST", "path": "/login", "params": ["username", "password"]},
        {"method": "GET", "path": "/about", "params": []},
        {"method": "GET", "path": "/contact", "params": []},
        {"method": "POST", "path": "/contact", "params": ["name", "email", "message"]},
        {"method": "GET", "path": "/products", "params": ["category", "sort"]},
        {"method": "GET", "path": "/product/{id}", "params": ["id"]},
        {"method": "GET", "path": "/search", "params": ["q", "page"]},
        {"method": "GET", "path": "/user/profile", "params": []},
        {"method": "POST", "path": "/user/profile", "params": ["name", "email", "bio"]},
        {"method": "GET", "path": "/api/products", "params": ["category", "limit"]},
        {"method": "GET", "path": "/api/product/{id}", "params": ["id"]},
        {"method": "POST", "path": "/api/cart/add", "params": ["product_id", "quantity"]},
        {"method": "GET", "path": "/cart", "params": []},
        {"method": "POST", "path": "/checkout", "params": ["payment_method", "shipping_address"]}
    ]

    # Advanced paths that would be found in deeper scans
    advanced_paths = [
        {"method": "GET", "path": "/admin", "params": []},
        {"method": "GET", "path": "/admin/users", "params": ["page", "sort"]},
        {"method": "GET", "path": "/admin/user/{id}", "params": ["id"]},
        {"method": "POST", "path": "/admin/user/{id}", "params": ["id", "name", "email", "role"]},
        {"method": "DELETE", "path": "/admin/user/{id}", "params": ["id"]},
        {"method": "GET", "path": "/admin/settings", "params": []},
        {"method": "POST", "path": "/admin/settings", "params": ["site_name", "maintenance_mode"]},
        {"method": "GET", "path": "/api/users", "params": ["page", "limit"]},
        {"method": "POST", "path": "/api/user", "params": ["name", "email", "password"]},
        {"method": "GET", "path": "/api/user/{id}", "params": ["id"]},
        {"method": "PUT", "path": "/api/user/{id}", "params": ["id", "name", "email"]},
        {"method": "DELETE", "path": "/api/user/{id}", "params": ["id"]},
        {"method": "GET", "path": "/api/orders", "params": ["user_id", "status"]},
        {"method": "GET", "path": "/api/order/{id}", "params": ["id"]},
        {"method": "PUT", "path": "/api/order/{id}", "params": ["id", "status"]},
        {"method": "GET", "path": "/api/stats", "params": ["period", "type"]},
        {"method": "GET", "path": "/newsletter/subscribe", "params": ["email"]},
        {"method": "POST", "path": "/password/reset", "params": ["email"]},
        {"method": "POST", "path": "/password/update", "params": ["token", "password", "password_confirmation"]}
    ]

    # Determine how many paths to include based on depth
    if depth <= 2:
        # For shallow scans, include only common paths
        site_map = common_paths[:int(len(common_paths) * depth / 3)]
    else:
        # For deeper scans, include common paths and some advanced paths
        advanced_count = int((depth - 2) * len(advanced_paths) / 3)
        site_map = common_paths + advanced_paths[:advanced_count]

    return site_map
