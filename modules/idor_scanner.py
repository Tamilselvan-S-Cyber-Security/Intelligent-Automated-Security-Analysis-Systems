"""
Insecure Direct Object Reference (IDOR) vulnerability scanner module

API Documentation
================

The IDORScanner module provides a comprehensive API for detecting Insecure Direct Object Reference vulnerabilities.

Class: IDORScanner
-----------------

Constructor:
    IDORScanner(timeout=10, verbose=False)
    
    Parameters:
        timeout (int): Request timeout in seconds (default: 10)
        verbose (bool): Enable verbose output (default: False)

Methods:
    scan(url, api_key=None)
        Scan a URL for IDOR vulnerabilities
        
        Parameters:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
            
        Returns:
            list: List of found vulnerabilities, each containing:
                - type (str): Vulnerability type ('IDOR')
                - endpoint (str): Vulnerable endpoint URL
                - method (str): HTTP method used
                - parameter (str): Vulnerable parameter name
                - original_id (str): Original ID value
                - test_id (str): Test ID value used
                - status_code (int): HTTP status code
                - response_length (int): Response length
                - evidence (str): Vulnerability evidence
                - confidence (str): Confidence level (low/medium/high)
                - source (str): Source of detection

API Integration
--------------
The scanner integrates with external security APIs for enhanced scanning:

1. Vulnerability Check API
   Endpoint: https://api.security.com/v1/vulnerabilities/check
   Method: POST
   Request Body:
   {
       "url": "target_url",
       "scan_type": "idor",
       "options": {
           "deep_scan": true,
           "check_patterns": true,
           "validate_ids": true
       }
   }

2. Pattern Analysis API
   Endpoint: https://api.security.com/v1/patterns/analyze
   Method: POST
   Request Body:
   {
       "url": "target_url",
       "patterns": ["id_patterns"],
       "parameters": ["id_params"]
   }

3. ID Validation API
   Endpoint: https://api.security.com/v1/ids/validate
   Method: POST
   Request Body:
   {
       "url": "target_url",
       "ids": {"param": "value"}
   }

4. Endpoint Scanning API
   Endpoint: https://api.security.com/v1/endpoints/scan
   Method: POST
   Request Body:
   {
       "url": "target_url",
       "scan_depth": 3,
       "check_methods": ["GET", "POST", "PUT", "DELETE"]
   }

Example Usage:
-------------
```python
from modules.idor_scanner import IDORScanner

# Initialize scanner
scanner = IDORScanner(timeout=10, verbose=True)

# Basic scan
vulnerabilities = scanner.scan('https://example.com')

# Enhanced scan with API
api_key = "your_api_key_here"
vulnerabilities = scanner.scan('https://example.com', api_key=api_key)

# Process results
for vuln in vulnerabilities:
    print(f"Found {vuln['type']} vulnerability:")
    print(f"  Endpoint: {vuln['endpoint']}")
    print(f"  Method: {vuln['method']}")
    print(f"  Parameter: {vuln['parameter']}")
    print(f"  Confidence: {vuln['confidence']}")
    print(f"  Source: {vuln['source']}")
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

3. Application Errors:
   - Invalid URL format
   - Missing required parameters
   - Response parsing errors

All errors are logged and reported with appropriate error messages.

Configuration:
-------------
The scanner can be configured through the constructor:

1. Timeout:
   - Controls request timeout in seconds
   - Default: 10 seconds
   - Recommended: 15-30 seconds for slow networks

2. Verbose Mode:
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

Version History:
---------------
1.0.0 - Initial release
1.1.0 - Added API integration
1.2.0 - Enhanced error handling
1.3.0 - Improved documentation
"""

import logging
import requests
import random
import re
import json
from bs4 import BeautifulSoup
from colorama import Fore, Style
from urllib.parse import urljoin, urlparse, parse_qs

logger = logging.getLogger('CyberWolf.IDORScanner')

class IDORScanner:
    """
    Scanner module for detecting Insecure Direct Object Reference (IDOR) vulnerabilities
    """
    
    def __init__(self, timeout=10, verbose=False):
        """
        Initialize the IDOR scanner
        
        Args:
            timeout (int): Request timeout in seconds
            verbose (bool): Enable verbose output
        """
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
        ]
        
        # Common ID patterns to test
        self.id_patterns = [
            r'\b\d{1,10}\b',  # Numeric IDs
            r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b',  # UUIDs
            r'\b[A-Za-z0-9]{24}\b',  # MongoDB ObjectIds
            r'\b[A-Za-z0-9]{32}\b',  # MD5 hashes
            r'\b[A-Za-z0-9]{40}\b',  # SHA-1 hashes
            r'\b[A-Za-z0-9]{64}\b',  # SHA-256 hashes
            r'\b[A-Za-z0-9]{8,}\b'  # Generic alphanumeric IDs
        ]
        
        # Common ID parameter names
        self.id_params = [
            'id', 'user_id', 'uid', 'account_id', 'order_id', 'invoice_id',
            'document_id', 'file_id', 'post_id', 'comment_id', 'message_id',
            'product_id', 'item_id', 'transaction_id', 'payment_id', 'ticket_id',
            'case_id', 'report_id', 'profile_id', 'customer_id', 'client_id',
            'employee_id', 'student_id', 'patient_id', 'record_id', 'object_id'
        ]
        
        # API endpoints for enhanced scanning
        self.api_endpoints = {
            'vuln_check': 'https://api.security.com/v1/vulnerabilities/check',
            'pattern_analysis': 'https://api.security.com/v1/patterns/analyze',
            'id_validation': 'https://api.security.com/v1/ids/validate',
            'endpoint_scan': 'https://api.security.com/v1/endpoints/scan'
        }
    
    def scan(self, url, api_key=None):
        """
        Scan the given URL for IDOR vulnerabilities
        
        Args:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
        
        Returns:
            list: Found IDOR vulnerabilities
        """
        logger.info(f"Starting IDOR scan on {url}")
        vulnerabilities = []
        
        try:
            # Find potential IDOR endpoints
            idor_endpoints = self._find_idor_endpoints(url)
            
            if not idor_endpoints:
                self._log_verbose("No potential IDOR endpoints found")
                return vulnerabilities
            
            # Test each endpoint for IDOR vulnerabilities
            for endpoint in idor_endpoints:
                self._log_verbose(f"Testing endpoint: {endpoint}")
                
                # Extract IDs from the endpoint
                ids = self._extract_ids(endpoint)
                
                if not ids:
                    self._log_verbose(f"No IDs found in endpoint: {endpoint}")
                    continue
                
                # Test each ID for IDOR vulnerabilities
                for id_param, id_value in ids.items():
                    try:
                        # Test with different ID values
                        test_ids = self._generate_test_ids(id_value)
                        
                        for test_id in test_ids:
                            # Replace the ID in the URL
                            test_url = self._replace_id_in_url(endpoint, id_param, test_id)
                            
                            # Test with different HTTP methods
                            for method in ['GET', 'POST', 'PUT', 'DELETE']:
                                try:
                                    if method == 'GET':
                                        response = self.session.get(
                                            test_url,
                                            headers={'User-Agent': random.choice(self.user_agents)},
                                            timeout=self.timeout,
                                            verify=True
                                        )
                                    elif method == 'POST':
                                        response = self.session.post(
                                            test_url,
                                            headers={'User-Agent': random.choice(self.user_agents)},
                                            timeout=self.timeout,
                                            verify=True
                                        )
                                    elif method == 'PUT':
                                        response = self.session.put(
                                            test_url,
                                            headers={'User-Agent': random.choice(self.user_agents)},
                                            timeout=self.timeout,
                                            verify=True
                                        )
                                    else:  # DELETE
                                        response = self.session.delete(
                                            test_url,
                                            headers={'User-Agent': random.choice(self.user_agents)},
                                            timeout=self.timeout,
                                            verify=True
                                        )
                                    
                                    # Check for IDOR indicators in response
                                    if self._is_vulnerable_to_idor(response, id_value, test_id):
                                        vuln = {
                                            'type': 'IDOR',
                                            'endpoint': endpoint,
                                            'method': method,
                                            'parameter': id_param,
                                            'original_id': id_value,
                                            'test_id': test_id,
                                            'status_code': response.status_code,
                                            'response_length': len(response.text),
                                            'evidence': response.text[:200]  # First 200 chars of response
                                        }
                                        vulnerabilities.append(vuln)
                                        self._log_verbose(f"Found IDOR vulnerability at {endpoint} using {method}")
                                except requests.RequestException as e:
                                    logger.error(f"Error testing IDOR payload: {str(e)}")
                                    continue
                    except Exception as e:
                        logger.error(f"Error processing ID parameter {id_param}: {str(e)}")
                        continue
            
            # Use API for enhanced scanning if available
            if api_key:
                self._log_verbose("Using API for enhanced IDOR scanning")
                api_vulns = self._api_enhanced_scan(url, api_key)
                vulnerabilities.extend(api_vulns)
            
            logger.info(f"IDOR scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error during IDOR scan: {str(e)}")
            print(f"{Fore.RED}[!] Error during IDOR scan: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _find_idor_endpoints(self, url):
        """
        Find potential IDOR endpoints on the target
        
        Args:
            url (str): Target URL
        
        Returns:
            list: Potential IDOR endpoints
        """
        endpoints = []
        
        try:
            # Get the main page
            response = self.session.get(
                url,
                headers={'User-Agent': random.choice(self.user_agents)},
                timeout=self.timeout,
                verify=True
            )
            
            # Parse the page for potential IDOR endpoints
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for links with ID parameters
            for link in soup.find_all('a', href=True):
                href = link['href']
                if any(param in href.lower() for param in self.id_params):
                    full_url = urljoin(url, href)
                    endpoints.append(full_url)
            
            # Look for forms with ID parameters
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    full_url = urljoin(url, action)
                    endpoints.append(full_url)
            
            # Add common IDOR endpoints
            common_endpoints = [
                '/api/users/',
                '/api/accounts/',
                '/api/orders/',
                '/api/invoices/',
                '/api/documents/',
                '/api/files/',
                '/api/posts/',
                '/api/comments/',
                '/api/messages/',
                '/api/products/',
                '/api/items/',
                '/api/transactions/',
                '/api/payments/',
                '/api/tickets/',
                '/api/cases/',
                '/api/reports/',
                '/api/profiles/',
                '/api/customers/',
                '/api/clients/',
                '/api/employees/',
                '/api/students/',
                '/api/patients/',
                '/api/records/'
            ]
            
            for endpoint in common_endpoints:
                full_url = urljoin(url, endpoint)
                endpoints.append(full_url)
            
            # Remove duplicates
            endpoints = list(set(endpoints))
            
            return endpoints
            
        except Exception as e:
            logger.error(f"Error finding IDOR endpoints: {str(e)}")
            return []
    
    def _extract_ids(self, url):
        """
        Extract IDs from the URL
        
        Args:
            url (str): Target URL
        
        Returns:
            dict: Extracted IDs and their parameter names
        """
        ids = {}
        
        try:
            # Parse URL parameters
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            # Check for ID parameters
            for param in self.id_params:
                if param in params:
                    ids[param] = params[param][0]
            
            # Check path segments for IDs
            path_segments = parsed_url.path.split('/')
            for segment in path_segments:
                for pattern in self.id_patterns:
                    match = re.search(pattern, segment)
                    if match:
                        # Try to guess the parameter name
                        param_name = None
                        for p in self.id_params:
                            if p in url.lower():
                                param_name = p
                                break
                        if not param_name:
                            param_name = 'id'
                        ids[param_name] = match.group(0)
            
            return ids
            
        except Exception as e:
            logger.error(f"Error extracting IDs: {str(e)}")
            return {}
    
    def _generate_test_ids(self, original_id):
        """
        Generate test IDs based on the original ID
        
        Args:
            original_id (str): Original ID value
        
        Returns:
            list: Generated test IDs
        """
        test_ids = []
        
        try:
            # Test with sequential IDs
            if original_id.isdigit():
                original_num = int(original_id)
                test_ids.extend([
                    str(original_num + 1),
                    str(original_num - 1),
                    str(original_num + 100),
                    str(original_num - 100)
                ])
            
            # Test with similar IDs
            if len(original_id) > 1:
                test_ids.extend([
                    original_id[:-1] + '0',
                    original_id[:-1] + '1',
                    original_id[:-1] + '9',
                    original_id[:-1] + 'a',
                    original_id[:-1] + 'f'
                ])
            
            # Test with common ID patterns
            test_ids.extend([
                '1',
                '0',
                'admin',
                'root',
                'test',
                'demo',
                'guest',
                'user',
                'admin123',
                'password123'
            ])
            
            # Remove duplicates
            test_ids = list(set(test_ids))
            
            return test_ids
            
        except Exception as e:
            logger.error(f"Error generating test IDs: {str(e)}")
            return []
    
    def _replace_id_in_url(self, url, param, new_id):
        """
        Replace an ID in the URL with a new value
        
        Args:
            url (str): Original URL
            param (str): Parameter name
            new_id (str): New ID value
        
        Returns:
            str: Modified URL
        """
        try:
            # Parse the URL
            parsed_url = urlparse(url)
            
            # Replace in query parameters
            params = parse_qs(parsed_url.query)
            if param in params:
                params[param] = [new_id]
                query = '&'.join(f"{k}={v[0]}" for k, v in params.items())
                url = url.replace(parsed_url.query, query)
            
            # Replace in path
            path_segments = parsed_url.path.split('/')
            for i, segment in enumerate(path_segments):
                if param in url.lower() and segment == params.get(param, [''])[0]:
                    path_segments[i] = new_id
            url = url.replace(parsed_url.path, '/'.join(path_segments))
            
            return url
            
        except Exception as e:
            logger.error(f"Error replacing ID in URL: {str(e)}")
            return url
    
    def _is_vulnerable_to_idor(self, response, original_id, test_id):
        """
        Check if the response indicates an IDOR vulnerability
        
        Args:
            response (requests.Response): Response object
            original_id (str): Original ID value
            test_id (str): Test ID value
        
        Returns:
            bool: True if vulnerable, False otherwise
        """
        # Check for common IDOR indicators
        indicators = [
            # Success indicators
            'success',
            'found',
            'exists',
            'valid',
            'authorized',
            
            # Data indicators
            'data',
            'content',
            'result',
            'response',
            'object',
            
            # User indicators
            'user',
            'account',
            'profile',
            'customer',
            'client',
            
            # Document indicators
            'document',
            'file',
            'record',
            'report',
            'case'
        ]
        
        # Check response content
        content = response.text.lower()
        
        # Check if any indicators are present
        for indicator in indicators:
            if indicator.lower() in content:
                return True
        
        # Check for specific status codes
        if response.status_code in [200, 201, 202, 203, 204]:
            return True
        
        # Check for unusual response length
        if len(response.text) > 100:  # Arbitrary threshold
            return True
        
        return False
    
    def _api_enhanced_scan(self, url, api_key):
        """
        Use API for enhanced IDOR scanning with improved features
        
        Args:
            url (str): Target URL
            api_key (str): API key for authentication
        
        Returns:
            list: Additional vulnerabilities found via API
        """
        vulnerabilities = []
        
        try:
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
                'User-Agent': random.choice(self.user_agents)
            }
            
            # 1. Enhanced Vulnerability Check
            self._log_verbose(f"{Fore.YELLOW}[API] Running enhanced vulnerability check...{Style.RESET_ALL}")
            vuln_data = {
                'url': url,
                'scan_type': 'idor',
                'options': {
                    'deep_scan': True,
                    'check_patterns': True,
                    'validate_ids': True
                }
            }
            
            response = self.session.post(
                self.api_endpoints['vuln_check'],
                headers=headers,
                json=vuln_data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                vuln_results = response.json()
                if vuln_results.get('vulnerabilities'):
                    for vuln in vuln_results['vulnerabilities']:
                        vulnerabilities.append({
                            'type': 'IDOR',
                            'endpoint': vuln.get('endpoint', url),
                            'method': vuln.get('method', 'GET'),
                            'parameter': vuln.get('parameter', 'id'),
                            'original_id': vuln.get('original_id', ''),
                            'test_id': vuln.get('test_id', ''),
                            'status_code': vuln.get('status_code', 200),
                            'response_length': vuln.get('response_length', 0),
                            'evidence': vuln.get('evidence', ''),
                            'confidence': vuln.get('confidence', 'medium'),
                            'source': 'API'
                        })
            
            # 2. Pattern Analysis
            self._log_verbose(f"{Fore.YELLOW}[API] Analyzing ID patterns...{Style.RESET_ALL}")
            pattern_data = {
                'url': url,
                'patterns': self.id_patterns,
                'parameters': self.id_params
            }
            
            response = self.session.post(
                self.api_endpoints['pattern_analysis'],
                headers=headers,
                json=pattern_data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                pattern_results = response.json()
                if pattern_results.get('matches'):
                    for match in pattern_results['matches']:
                        vulnerabilities.append({
                            'type': 'IDOR',
                            'endpoint': match.get('endpoint', url),
                            'method': 'GET',
                            'parameter': match.get('parameter', 'id'),
                            'original_id': match.get('id', ''),
                            'test_id': match.get('suggested_id', ''),
                            'status_code': 200,
                            'response_length': 0,
                            'evidence': match.get('evidence', ''),
                            'confidence': match.get('confidence', 'low'),
                            'source': 'API Pattern Analysis'
                        })
            
            # 3. ID Validation
            self._log_verbose(f"{Fore.YELLOW}[API] Validating ID patterns...{Style.RESET_ALL}")
            id_data = {
                'url': url,
                'ids': self._extract_ids(url)
            }
            
            response = self.session.post(
                self.api_endpoints['id_validation'],
                headers=headers,
                json=id_data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                validation_results = response.json()
                if validation_results.get('invalid_ids'):
                    for invalid_id in validation_results['invalid_ids']:
                        vulnerabilities.append({
                            'type': 'IDOR',
                            'endpoint': invalid_id.get('endpoint', url),
                            'method': 'GET',
                            'parameter': invalid_id.get('parameter', 'id'),
                            'original_id': invalid_id.get('id', ''),
                            'test_id': invalid_id.get('suggested_id', ''),
                            'status_code': 200,
                            'response_length': 0,
                            'evidence': invalid_id.get('evidence', ''),
                            'confidence': invalid_id.get('confidence', 'high'),
                            'source': 'API ID Validation'
                        })
            
            # 4. Endpoint Scanning
            self._log_verbose(f"{Fore.YELLOW}[API] Scanning for vulnerable endpoints...{Style.RESET_ALL}")
            endpoint_data = {
                'url': url,
                'scan_depth': 3,
                'check_methods': ['GET', 'POST', 'PUT', 'DELETE']
            }
            
            response = self.session.post(
                self.api_endpoints['endpoint_scan'],
                headers=headers,
                json=endpoint_data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                endpoint_results = response.json()
                if endpoint_results.get('vulnerable_endpoints'):
                    for endpoint in endpoint_results['vulnerable_endpoints']:
                        vulnerabilities.append({
                            'type': 'IDOR',
                            'endpoint': endpoint.get('url', url),
                            'method': endpoint.get('method', 'GET'),
                            'parameter': endpoint.get('parameter', 'id'),
                            'original_id': endpoint.get('id', ''),
                            'test_id': endpoint.get('test_id', ''),
                            'status_code': endpoint.get('status_code', 200),
                            'response_length': endpoint.get('response_length', 0),
                            'evidence': endpoint.get('evidence', ''),
                            'confidence': endpoint.get('confidence', 'medium'),
                            'source': 'API Endpoint Scan'
                        })
            
            # Print API scan summary
            self._print_api_summary(vulnerabilities)
            
            return vulnerabilities
            
        except requests.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            print(f"{Fore.RED}[!] API request failed: {str(e)}{Style.RESET_ALL}")
            return []
        except Exception as e:
            logger.error(f"Error during API enhanced scan: {str(e)}")
            print(f"{Fore.RED}[!] Error during API enhanced scan: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _print_api_summary(self, vulnerabilities):
        """Print a summary of API scan results"""
        if not vulnerabilities:
            print(f"{Fore.YELLOW}[API] No additional vulnerabilities found through API scanning{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}=== API Enhanced Scan Results ==={Style.RESET_ALL}")
        print(f"{Fore.GREEN}Found {len(vulnerabilities)} additional vulnerabilities through API scanning{Style.RESET_ALL}")
        
        # Group vulnerabilities by source
        by_source = {}
        for vuln in vulnerabilities:
            source = vuln.get('source', 'Unknown')
            if source not in by_source:
                by_source[source] = []
            by_source[source].append(vuln)
        
        # Print results by source
        for source, vulns in by_source.items():
            print(f"\n{Fore.YELLOW}[{source}]{Style.RESET_ALL}")
            for vuln in vulns:
                print(f"  {Fore.GREEN}+{Style.RESET_ALL} {vuln['endpoint']}")
                print(f"    Method: {vuln['method']}")
                print(f"    Parameter: {vuln['parameter']}")
                print(f"    Confidence: {vuln.get('confidence', 'unknown')}")
        
        print(f"\n{Fore.CYAN}=== End of API Results ==={Style.RESET_ALL}\n")
    
    def _log_verbose(self, message):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            logger.debug(message)
            print(f"{Fore.CYAN}[IDOR] {message}{Style.RESET_ALL}") 