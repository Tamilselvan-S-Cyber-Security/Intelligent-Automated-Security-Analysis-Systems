#!/usr/bin/env python3
"""
Intelligent Automated Security Analysis System
An Intelligent Automated Security Analysis System for Applications, Websites, and Files
Developed by Security Team - SKP Engineering College, CSE 4th Year | Final Year Project

API Documentation
================

This Intelligent Security Analysis System provides a comprehensive API for detecting various web application vulnerabilities.

Class: VulnerabilityScanner
--------------------------

Constructor:
    VulnerabilityScanner(url, timeout=10, api_key=None, verbose=False)
    
    Parameters:
        url (str): Target URL to scan
        timeout (int): Request timeout in seconds (default: 10)
        api_key (str, optional): API key for enhanced scanning
        verbose (bool): Enable verbose output (default: False)

Methods:
    run_all_scans(options=None)
        Execute selected scanning modules and aggregate results
        
        Parameters:
            options (dict, optional): Dictionary of scanning options
                Example: {
                    'xss': True,
                    'sqli': True,
                    'ports': True,
                    'paths': True,
                    'misconfig': True,
                    'xxe': True,
                    'ssrf': True,
                    'rce': True,
                    'idor': True
                }
            
        Returns:
            dict: Scan results containing:
                - xss: List of XSS vulnerabilities
                - sqli: List of SQL injection vulnerabilities
                - ports: List of open ports
                - paths: List of vulnerable paths
                - misconfig: List of misconfigurations
                - xxe: List of XXE vulnerabilities
                - ssrf: List of SSRF vulnerabilities
                - rce: List of RCE vulnerabilities
                - idor: List of IDOR vulnerabilities
                - summary: Dictionary with:
                    - total_vulnerabilities: Total count
                    - risk_level: Overall risk level
                    - Per-scan type counts

API Integration
--------------
The scanner integrates with external security APIs for enhanced scanning:

1. Vulnerability Check API
   Endpoint: https://api.security.com/v1/vulnerabilities/check
   Method: POST
   Request Body:
   {
       "url": "target_url",
       "scan_types": ["xss", "sqli", "xxe", "ssrf", "rce", "idor"],
       "options": {
           "deep_scan": true,
           "check_patterns": true,
           "validate_inputs": true
       }
   }

2. Port Scanning API
   Endpoint: https://api.security.com/v1/ports/scan
   Method: POST
   Request Body:
   {
       "url": "target_url",
       "ports": [80, 443, 8080, 8443],
       "scan_type": "tcp"
   }

3. Path Discovery API
   Endpoint: https://api.security.com/v1/paths/discover
   Method: POST
   Request Body:
   {
       "url": "target_url",
       "depth": 3,
       "check_robots": true
   }

4. Configuration Check API
   Endpoint: https://api.security.com/v1/config/check
   Method: POST
   Request Body:
   {
       "url": "target_url",
       "checks": ["headers", "ssl", "cors", "csp"]
   }

Example Usage:
-------------
```python
from cyberwolf import VulnerabilityScanner

# Initialize scanner
scanner = VulnerabilityScanner(
    url='https://example.com',
    timeout=15,
    api_key='your_api_key_here',
    verbose=True
)

# Run all scans
results = scanner.run_all_scans()

# Run specific scans
results = scanner.run_all_scans({
    'xss': True,
    'sqli': True,
    'ports': False,
    'paths': True
})

# Process results
print(f"Total vulnerabilities: {results['summary']['total_vulnerabilities']}")
print(f"Risk level: {results['summary']['risk_level']}")

for scan_type, vulns in results.items():
    if scan_type != 'summary':
        print(f"\n{scan_type.upper()} vulnerabilities:")
        for vuln in vulns:
            print(f"  - {vuln['type']} at {vuln['endpoint']}")
            print(f"    Method: {vuln['method']}")
            print(f"    Parameter: {vuln['parameter']}")
            print(f"    Evidence: {vuln['evidence'][:100]}...")
```

Error Handling:
--------------
The scanner provides comprehensive error handling:

1. API Errors:
   - Invalid API key
   - API service unavailable
   - Rate limiting
   - Invalid request format

2. Network Errors:
   - Connection timeout
   - DNS resolution failure
   - SSL/TLS errors
   - Port scanning errors

3. Application Errors:
   - Invalid URL format
   - Missing required parameters
   - Response parsing errors
   - Scanner initialization errors

All errors are logged and reported with appropriate error messages.

Configuration:
-------------
The scanner can be configured through the constructor:

1. Timeout:
   - Controls request timeout in seconds
   - Default: 10 seconds
   - Recommended: 15-30 seconds for slow networks

2. API Key:
   - Required for enhanced scanning
   - Should be stored securely
   - Can be None for basic scanning

3. Verbose Mode:
   - Enables detailed logging
   - Shows scan progress
   - Displays API interaction details
   - Default: False

Security Considerations:
----------------------
1. API Key Security:
   - Never hardcode API keys
   - Use environment variables
   - Rotate keys regularly

2. Rate Limiting:
   - Respect API rate limits
   - Implement exponential backoff
   - Handle 429 responses

3. Data Privacy:
   - Sanitize sensitive data
   - Remove credentials from logs
   - Handle PII appropriately

4. Network Security:
   - Use HTTPS for all requests
   - Validate SSL certificates
   - Implement proper timeout handling

Dependencies:
------------
- requests
- beautifulsoup4
- colorama
- urllib3
- logging
- concurrent.futures
- socket
- re
- random

Version History:
---------------
1.0.0 - Initial release
1.1.0 - Added API integration
1.2.0 - Enhanced error handling
1.3.0 - Improved documentation
1.4.0 - Added concurrent scanning
"""

import os
import sys
import argparse
import logging
import json
import secrets
import string
from datetime import datetime, timedelta
from colorama import init, Fore, Style
from flask import Flask, request, jsonify
from flask_restful import Api, Resource

from modules.scanner import VulnerabilityScanner
from utils.banner import display_banner
from utils.validator import validate_url
from utils.reporter import generate_report
from config import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('CyberWolf')

# Default API key for enhanced scanning
DEFAULT_API_KEY = 'AIzaSyABge7vHFTpvZykbQd_EDvoT35-eSvZp2s'

class APIKeyManager:
    """Manages API key generation, validation, and storage"""
    
    def __init__(self, key_file='api_keys.json'):
        self.key_file = key_file
        self.keys = self._load_keys()
        # Add default key if not exists
        if DEFAULT_API_KEY not in self.keys:
            self.keys[DEFAULT_API_KEY] = {
                'name': 'Default Enhanced Key',
                'description': 'Fixed API key for enhanced scanning',
                'created_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(days=3650)).isoformat(),  # 10 years
                'is_active': True,
                'usage_count': 0,
                'last_used': None
            }
            self._save_keys()
    
    def _load_keys(self):
        """Load API keys from file"""
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error loading API keys: {str(e)}")
            return {}
    
    def _save_keys(self):
        """Save API keys to file"""
        try:
            with open(self.key_file, 'w') as f:
                json.dump(self.keys, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Error saving API keys: {str(e)}")
            return False
    
    def generate_key(self, name, description=None, expiry_days=30):
        """Generate a new API key"""
        try:
            # Generate a secure random key
            alphabet = string.ascii_letters + string.digits
            key = ''.join(secrets.choice(alphabet) for _ in range(32))
            
            # Create key metadata
            now = datetime.now()
            expiry_date = now + timedelta(days=expiry_days)
            
            key_data = {
                'name': name,
                'description': description,
                'created_at': now.isoformat(),
                'expires_at': expiry_date.isoformat(),
                'is_active': True,
                'usage_count': 0,
                'last_used': None
            }
            
            # Store the key
            self.keys[key] = key_data
            self._save_keys()
            
            return key, key_data
        except Exception as e:
            logger.error(f"Error generating API key: {str(e)}")
            return None, None
    
    def validate_key(self, key):
        """Validate an API key"""
        if key not in self.keys:
            return False
        
        key_data = self.keys[key]
        
        # Check if key is active
        if not key_data['is_active']:
            return False
        
        # Check if key has expired
        expires_at = datetime.fromisoformat(key_data['expires_at'])
        if datetime.now() > expires_at:
            return False
        
        # Update usage stats
        key_data['usage_count'] += 1
        key_data['last_used'] = datetime.now().isoformat()
        self._save_keys()
        
        return True
    
    def revoke_key(self, key):
        """Revoke an API key"""
        if key in self.keys:
            self.keys[key]['is_active'] = False
            self._save_keys()
            return True
        return False
    
    def list_keys(self):
        """List all API keys"""
        return self.keys
    
    def get_key_info(self, key):
        """Get information about a specific key"""
        return self.keys.get(key)

# Initialize API key manager
api_key_manager = APIKeyManager()

# Initialize Flask app for API
app = Flask(__name__)
api = Api(app)

class APIKeyResource(Resource):
    """API endpoint for API key management"""
    
    def post(self):
        """Generate a new API key"""
        try:
            data = request.get_json()
            name = data.get('name')
            description = data.get('description')
            expiry_days = data.get('expiry_days', 30)
            
            if not name:
                return {'error': 'Name is required'}, 400
            
            key, key_data = api_key_manager.generate_key(name, description, expiry_days)
            
            if not key:
                return {'error': 'Failed to generate API key'}, 500
            
            return {
                'api_key': key,
                'key_info': key_data
            }, 201
            
        except Exception as e:
            return {'error': str(e)}, 500
    
    def get(self):
        """List all API keys (admin only)"""
        try:
            # In a real implementation, add authentication here
            return {'keys': api_key_manager.list_keys()}, 200
        except Exception as e:
            return {'error': str(e)}, 500
    
    def delete(self):
        """Revoke an API key"""
        try:
            data = request.get_json()
            key = data.get('api_key')
            
            if not key:
                return {'error': 'API key is required'}, 400
            
            if api_key_manager.revoke_key(key):
                return {'message': 'API key revoked successfully'}, 200
            return {'error': 'API key not found'}, 404
            
        except Exception as e:
            return {'error': str(e)}, 500

class ScanAPI(Resource):
    def post(self):
        try:
            data = request.get_json()
            url = data.get('url')
            timeout = data.get('timeout', DEFAULT_TIMEOUT)
            api_key = data.get('api_key')
            attack_options = data.get('attack_options', {})
            
            if not url:
                return {'error': 'URL is required'}, 400
                
            if not validate_url(url):
                return {'error': 'Invalid URL format'}, 400
            
            # Validate API key if provided
            if api_key and not api_key_manager.validate_key(api_key):
                return {'error': 'Invalid or expired API key'}, 401
                
            scanner = VulnerabilityScanner(
                url=url,
                timeout=timeout,
                api_key=api_key,
                verbose=False
            )
            
            results = scanner.run_all_scans(attack_options)
            return {'results': results}, 200
            
        except Exception as e:
            return {'error': str(e)}, 500

# Add API resources
api.add_resource(ScanAPI, '/api/scan')
api.add_resource(APIKeyResource, '/api/keys')

def generate_api_docs():
    """Generate API documentation."""
    docs = {
        'endpoints': {
            '/api/scan': {
                'method': 'POST',
                'description': 'Perform vulnerability scan on target URL',
                'parameters': {
                    'url': {
                        'type': 'string',
                        'required': True,
                        'description': 'Target URL to scan'
                    },
                    'timeout': {
                        'type': 'integer',
                        'required': False,
                        'default': DEFAULT_TIMEOUT,
                        'description': 'Request timeout in seconds'
                    },
                    'api_key': {
                        'type': 'string',
                        'required': False,
                        'description': 'API key for enhanced scanning'
                    },
                    'attack_options': {
                        'type': 'object',
                        'required': False,
                        'description': 'Custom attack options'
                    }
                },
                'response': {
                    '200': {
                        'description': 'Successful scan',
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'results': {
                                            'type': 'object',
                                            'description': 'Scan results'
                                        }
                                    }
                                }
                            }
                        }
                    },
                    '400': {
                        'description': 'Bad request',
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'error': {
                                            'type': 'string',
                                            'description': 'Error message'
                                        }
                                    }
                                }
                            }
                        }
                    },
                    '401': {
                        'description': 'Unauthorized',
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'error': {
                                            'type': 'string',
                                            'description': 'Invalid API key'
                                        }
                                    }
                                }
                            }
                        }
                    },
                    '500': {
                        'description': 'Server error',
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'error': {
                                            'type': 'string',
                                            'description': 'Error message'
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            '/api/keys': {
                'method': 'POST',
                'description': 'Generate a new API key',
                'parameters': {
                    'name': {
                        'type': 'string',
                        'required': True,
                        'description': 'Name for the API key'
                    },
                    'description': {
                        'type': 'string',
                        'required': False,
                        'description': 'Description of the API key usage'
                    },
                    'expiry_days': {
                        'type': 'integer',
                        'required': False,
                        'default': 30,
                        'description': 'Number of days until key expires'
                    }
                },
                'response': {
                    '201': {
                        'description': 'API key generated successfully',
                       
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'api_key': {
                                            'type': 'string',
                                            'description': 'Generated API key'
                                        },
                                        'key_info': {
                                            'type': 'object',
                                            'description': 'Key metadata'
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return docs

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='CyberWolf - Automated Vulnerability Scanner',
        epilog='Developed By CyberWolf Team'
    )
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT, 
                        help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('-a', '--api-key', help='API key for enhanced scanning')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-o', '--output', help='Output file for the report')
    parser.add_argument('--api', action='store_true', help='Start API server')
    parser.add_argument('--api-host', default='127.0.0.1', help='API server host (default: 127.0.0.1)')
    parser.add_argument('--api-port', type=int, default=5000, help='API server port (default: 5000)')
    parser.add_argument('--generate-api-docs', action='store_true', help='Generate API documentation')
    
    # Custom attack options
    attack_group = parser.add_argument_group('Attack Options')
    attack_group.add_argument('--no-xss', action='store_true', help='Disable XSS scanning')
    attack_group.add_argument('--no-sqli', action='store_true', help='Disable SQL Injection scanning')
    attack_group.add_argument('--no-ports', action='store_true', help='Disable Port scanning')
    attack_group.add_argument('--no-paths', action='store_true', help='Disable Path scanning')
    attack_group.add_argument('--no-misconfig', action='store_true', help='Disable Security Misconfiguration scanning')
    
    # Output format options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--format', choices=['text', 'html', 'pdf', 'json'], default='text',
                        help='Output format (text, html, pdf, or json)')
    output_group.add_argument('--save-evidence', action='store_true',
                        help='Include detailed evidence in reports')
    output_group.add_argument('--output-dir', default='./reports',
                        help='Directory to save reports (default: ./reports)')
    output_group.add_argument('--all-formats', action='store_true',
                        help='Generate reports in all available formats')
    
    return parser.parse_args()

def show_main_menu():
    """Display the main menu and get user choice."""
    print(f"\n{Fore.CYAN}=== CyberWolf Scanner Options ==={Style.RESET_ALL}")
    print(f"{Fore.WHITE}1. Auto Attack (Scan URL for all vulnerabilities)")
    print(f"2. Custom Attack (Select specific vulnerabilities to scan)")
    print(f"3. API Enhanced Scan")
    print(f"4. Start API Server")
    print(f"5. API Key Management")
    print(f"6. Help")
    print(f"7. Exit{Style.RESET_ALL}")
    
    choice = input(f"\n{Fore.GREEN}Enter your choice (1-7): {Style.RESET_ALL}")
    return choice

def get_url_input():
    """Get and validate URL input from user."""
    while True:
        url = input(f"\n{Fore.GREEN}Enter target URL (e.g., https://example.com): {Style.RESET_ALL}")
        if validate_url(url):
            return url
        print(f"{Fore.RED}Invalid URL format. Please try again.{Style.RESET_ALL}")

def get_api_key():
    """Get API key from user or environment variable."""
    # First check environment variables
    api_key = os.getenv("CYBERWOLF_API_KEY")
    
    if not api_key:
        print(f"\n{Fore.YELLOW}No API key found in environment variables.{Style.RESET_ALL}")
        api_key = input(f"{Fore.GREEN}Enter your API key (leave blank to skip): {Style.RESET_ALL}")
    
    return api_key if api_key else None

def auto_attack(url, timeout=DEFAULT_TIMEOUT, api_key=None, verbose=False, 
                attack_options=None, output_format='text', save_report=False, output_file=None):
    """
    Execute attack on the target URL with specified options.
    
    Args:
        url (str): Target URL to scan
        timeout (int): Timeout in seconds
        api_key (str, optional): API key for enhanced scanning
        verbose (bool): Enable verbose output
        attack_options (dict, optional): Dictionary of attack options 
                                        (xss, sqli, ports, paths, misconfig)
        output_format (str): Report format ('text', 'html', 'pdf', 'json')
        save_report (bool): Whether to save the report automatically
        output_file (str, optional): Output file path for the report
    """
    try:
        print(f"\n{Fore.CYAN}[+] Starting vulnerability scan on: {url}{Style.RESET_ALL}")
        
        scanner = VulnerabilityScanner(
            url=url,
            timeout=timeout,
            api_key=api_key,
            verbose=verbose
        )
        
        # Execute scans with specified options
        if attack_options:
            print(f"{Fore.CYAN}[+] Running custom scan with options: {attack_options}{Style.RESET_ALL}")
            results = scanner.run_all_scans(attack_options)
        else:
            print(f"{Fore.CYAN}[+] Running full scan with all attack types{Style.RESET_ALL}")
            results = scanner.run_all_scans()
        
        # Import the advanced report generator
        from utils.report_generator import ReportGenerator
        
        # Create report generator
        report_gen = ReportGenerator(url, results)
        
        # Generate text report for console display
        if verbose:
            print(f"{Fore.CYAN}[+] Generating report...{Style.RESET_ALL}")
            
        # Display the text report on console
        with open(report_gen.generate_text_report(), 'r') as f:
            text_report = f.read()
        print(text_report)
        
        # Handle report saving
        if save_report:
            # Use the specified output file or generate default filename
            if not output_file:
                output_file = f"cyberwolf_report.{output_format}"
                
            # Generate report in requested format
            if output_format == 'html':
                saved_file = report_gen.generate_html_report()
                print(f"{Fore.GREEN}[+] HTML report saved to {saved_file}{Style.RESET_ALL}")
            elif output_format == 'pdf':
                saved_file = report_gen.generate_pdf_report()
                print(f"{Fore.GREEN}[+] PDF report saved to {saved_file}{Style.RESET_ALL}")
            elif output_format == 'json':
                saved_file = report_gen.generate_json_report()
                print(f"{Fore.GREEN}[+] JSON report saved to {saved_file}{Style.RESET_ALL}")
            else:  # Default to text
                saved_file = report_gen.generate_text_report()
                print(f"{Fore.GREEN}[+] Text report saved to {saved_file}{Style.RESET_ALL}")
        else:
            # Ask if user wants to save the report
            save = input(f"\n{Fore.GREEN}Do you want to save the report? (y/n): {Style.RESET_ALL}")
            if save.lower() == 'y':
                # Ask for the format
                format_choice = input(f"{Fore.GREEN}Choose format (text/html/pdf/json, default: text): {Style.RESET_ALL}")
                format_choice = format_choice.lower() if format_choice else 'text'
                
                # Ask for filename
                filename = input(f"{Fore.GREEN}Enter filename (leave blank for default): {Style.RESET_ALL}")
                
                # Generate and save report based on chosen format
                if format_choice == 'html':
                    if not filename:
                        filename = f"cyberwolf_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.html"
                    report_gen.filename_base = os.path.splitext(filename)[0]
                    saved_file = report_gen.generate_html_report()
                    print(f"{Fore.GREEN}[+] HTML report saved to {saved_file}{Style.RESET_ALL}")
                elif format_choice == 'pdf':
                    if not filename:
                        filename = f"cyberwolf_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pdf"
                    report_gen.filename_base = os.path.splitext(filename)[0]
                    saved_file = report_gen.generate_pdf_report()
                    print(f"{Fore.GREEN}[+] PDF report saved to {saved_file}{Style.RESET_ALL}")
                elif format_choice == 'json':
                    if not filename:
                        filename = f"cyberwolf_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"
                    report_gen.filename_base = os.path.splitext(filename)[0]
                    saved_file = report_gen.generate_json_report()
                    print(f"{Fore.GREEN}[+] JSON report saved to {saved_file}{Style.RESET_ALL}")
                else:  # Default to text
                    if not filename:
                        filename = f"cyberwolf_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
                    report_gen.filename_base = os.path.splitext(filename)[0]
                    saved_file = report_gen.generate_text_report()
                    print(f"{Fore.GREEN}[+] Text report saved to {saved_file}{Style.RESET_ALL}")
            
        return True
    
    except Exception as e:
        logger.error(f"Error during attack: {str(e)}")
        print(f"{Fore.RED}Error during scan: {str(e)}{Style.RESET_ALL}")
        return False

def get_custom_attack_options():
    """Get custom attack options from user input."""
    print(f"\n{Fore.CYAN}=== Select Attack Types ==={Style.RESET_ALL}")
    
    attack_options = {}
    
    # XSS Scanning
    xss = input(f"{Fore.GREEN}Enable XSS scanning? (Y/n): {Style.RESET_ALL}")
    attack_options['xss'] = xss.lower() != 'n'
    
    # SQL Injection Scanning
    sqli = input(f"{Fore.GREEN}Enable SQL Injection scanning? (Y/n): {Style.RESET_ALL}")
    attack_options['sqli'] = sqli.lower() != 'n'
    
    # Port Scanning
    ports = input(f"{Fore.GREEN}Enable Port scanning? (Y/n): {Style.RESET_ALL}")
    attack_options['ports'] = ports.lower() != 'n'
    
    # Path Traversal Scanning
    paths = input(f"{Fore.GREEN}Enable Path/Directory scanning? (Y/n): {Style.RESET_ALL}")
    attack_options['paths'] = paths.lower() != 'n'
    
    # Validate at least one option is selected
    if not any(attack_options.values()):
        print(f"{Fore.YELLOW}[!] No attack types selected. Enabling XSS scanning by default.{Style.RESET_ALL}")
        attack_options['xss'] = True
    
    # Get timeout
    try:
        timeout_str = input(f"{Fore.GREEN}Enter scan timeout in seconds (5-60, default: {DEFAULT_TIMEOUT}): {Style.RESET_ALL}")
        timeout = int(timeout_str) if timeout_str else DEFAULT_TIMEOUT
        
        if timeout < 5 or timeout > 60:
            print(f"{Fore.YELLOW}[!] Invalid timeout. Using default: {DEFAULT_TIMEOUT} seconds{Style.RESET_ALL}")
            timeout = DEFAULT_TIMEOUT
    except ValueError:
        print(f"{Fore.YELLOW}[!] Invalid timeout. Using default: {DEFAULT_TIMEOUT} seconds{Style.RESET_ALL}")
        timeout = DEFAULT_TIMEOUT
        
    return attack_options, timeout

def show_api_key_menu():
    """Display API key management menu."""
    print(f"\n{Fore.CYAN}=== API Key Management ==={Style.RESET_ALL}")
    print(f"{Fore.WHITE}1. Generate new API key")
    print(f"2. List existing API keys")
    print(f"3. Revoke API key")
    print(f"4. Back to main menu{Style.RESET_ALL}")
    
    choice = input(f"\n{Fore.GREEN}Enter your choice (1-4): {Style.RESET_ALL}")
    return choice

def handle_api_key_generation():
    """Handle API key generation."""
    print(f"\n{Fore.CYAN}=== Generate New API Key ==={Style.RESET_ALL}")
    
    name = input(f"{Fore.GREEN}Enter key name: {Style.RESET_ALL}")
    if not name:
        print(f"{Fore.RED}Key name is required{Style.RESET_ALL}")
        return
    
    description = input(f"{Fore.GREEN}Enter key description (optional): {Style.RESET_ALL}")
    
    try:
        expiry_days = int(input(f"{Fore.GREEN}Enter expiry days (default: 30): {Style.RESET_ALL}") or 30)
    except ValueError:
        print(f"{Fore.RED}Invalid expiry days. Using default: 30{Style.RESET_ALL}")
        expiry_days = 30
    
    key, key_data = api_key_manager.generate_key(name, description, expiry_days)
    
    if key:
        print(f"\n{Fore.GREEN}[+] API Key generated successfully!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}API Key: {key}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Expires: {key_data['expires_at']}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}IMPORTANT: Save this key securely. It will not be shown again.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Failed to generate API key{Style.RESET_ALL}")

def handle_api_key_listing():
    """Handle API key listing."""
    print(f"\n{Fore.CYAN}=== Existing API Keys ==={Style.RESET_ALL}")
    
    keys = api_key_manager.list_keys()
    if not keys:
        print(f"{Fore.YELLOW}No API keys found{Style.RESET_ALL}")
        return
    
    for key, data in keys.items():
        print(f"\n{Fore.GREEN}Key: {key[:8]}...{key[-8:]}{Style.RESET_ALL}")
        print(f"Name: {data.get('name', 'Unnamed')}")
        print(f"Description: {data.get('description', 'None')}")
        print(f"Created: {data.get('created_at', 'Unknown')}")
        print(f"Expires: {data.get('expires_at', 'Never')}")
        print(f"Status: {'Active' if data.get('is_active', True) else 'Revoked'}")
        print(f"Usage Count: {data.get('usage_count', 0)}")
        print(f"Last Used: {data.get('last_used', 'Never')}")

def handle_api_key_revocation():
    """Handle API key revocation."""
    print(f"\n{Fore.CYAN}=== Revoke API Key ==={Style.RESET_ALL}")
    
    key = input(f"{Fore.GREEN}Enter API key to revoke: {Style.RESET_ALL}")
    if not key:
        print(f"{Fore.RED}API key is required{Style.RESET_ALL}")
        return
    
    if api_key_manager.revoke_key(key):
        print(f"{Fore.GREEN}API key revoked successfully{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}API key not found{Style.RESET_ALL}")

def show_help():
    """Display help information."""
    print(f"\n{Fore.CYAN}=== CyberWolf Help ==={Style.RESET_ALL}")
    print("CyberWolf is an automated vulnerability scanner that can detect:")
    print("- Cross-Site Scripting (XSS) vulnerabilities")
    print("- SQL Injection vulnerabilities")
    print("- Open ports and services")
    print("- Directory traversal and path vulnerabilities")
    print("- And more...")
    print("\nBasic usage:")
    print("1. Select 'Auto Attack' to scan a URL for all vulnerabilities")
    print("2. Select 'Custom Attack' to choose specific types of vulnerabilities to scan")
    print("3. Select 'API Enhanced Scan' to use advanced API-based scanning")
    print("\nCommand-line options:")
    print("  cyberwolf.py -u <URL> [-t TIMEOUT] [-a API_KEY] [-v] [-o OUTPUT_FILE]")
    print("\nExample:")
    print("  ./cyberwolf.py -u https://example.com -v -o report.txt")
    
    input(f"\n{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL}")

def main():
    """Main function."""
    display_banner()
    
    args = parse_arguments()
    
    # Handle API documentation generation
    if args.generate_api_docs:
        docs = generate_api_docs()
        with open('api_docs.json', 'w') as f:
            json.dump(docs, f, indent=4)
        print(f"{Fore.GREEN}[+] API documentation generated in api_docs.json{Style.RESET_ALL}")
        return
    
    # Handle API server start
    if args.api:
        print(f"{Fore.CYAN}[+] Starting API server on {args.api_host}:{args.api_port}{Style.RESET_ALL}")
        app.run(host=args.api_host, port=args.api_port)
        return
    
    # If URL is provided via command line, run scan directly
    if args.url:
        attack_options = {
            'xss': not args.no_xss,
            'sqli': not args.no_sqli,
            'ports': not args.no_ports,
            'paths': not args.no_paths,
            'misconfig': not args.no_misconfig
        }
        
        auto_attack(
            url=args.url,
            timeout=args.timeout,
            api_key=args.api_key,
            verbose=args.verbose,
            attack_options=attack_options,
            output_format=args.format,
            save_report=True,
            output_file=args.output
        )
        return
    
    # Interactive mode
    while True:
        choice = show_main_menu()
        
        if choice == '1':  # Auto Attack
            url = get_url_input()
            api_key = get_api_key()
            auto_attack(url, api_key=api_key)
            
        elif choice == '2':  # Custom Attack
            url = get_url_input()
            attack_options, timeout = get_custom_attack_options()
            api_key = get_api_key()
            auto_attack(url, timeout, api_key, attack_options=attack_options)
            
        elif choice == '3':  # API Enhanced Scan
            url = get_url_input()
            api_key = get_api_key()
            if not api_key:
                print(f"{Fore.RED}API key is required for enhanced scanning{Style.RESET_ALL}")
                continue
            auto_attack(url, api_key=api_key)
            
        elif choice == '4':  # Start API Server
            host = input(f"{Fore.GREEN}Enter API server host (default: 127.0.0.1): {Style.RESET_ALL}") or '127.0.0.1'
            port = input(f"{Fore.GREEN}Enter API server port (default: 5000): {Style.RESET_ALL}") or '5000'
            print(f"{Fore.CYAN}[+] Starting API server on {host}:{port}{Style.RESET_ALL}")
            app.run(host=host, port=int(port))
            
        elif choice == '5':  # API Key Management
            while True:
                api_choice = show_api_key_menu()
                
                if api_choice == '1':  # Generate new key
                    handle_api_key_generation()
                    
                elif api_choice == '2':  # List keys
                    handle_api_key_listing()
                    
                elif api_choice == '3':  # Revoke key
                    handle_api_key_revocation()
                    
                elif api_choice == '4':  # Back to main menu
                    break
                    
                else:
                    print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")
            
        elif choice == '6':  # Help
            show_help()
            
        elif choice == '7':  # Exit
            print(f"{Fore.CYAN}[+] Thank you for using CyberWolf!{Style.RESET_ALL}")
            sys.exit(0)
            
        else:
            print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
