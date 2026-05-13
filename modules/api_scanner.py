"""
API security vulnerability scanner module
"""

import re
import logging
import random
import requests
import json
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style

logger = logging.getLogger('CyberWolf.APIScanner')

class APIScanner:
    """
    Scanner module for detecting API security vulnerabilities
    """
    
    def __init__(self, timeout=10, verbose=False):
        """
        Initialize the API scanner
        
        Args:
            timeout (int): Request timeout in seconds
            verbose (bool): Enable verbose output
        """
        self.timeout = timeout
        self.verbose = verbose
        
        # User agent to mimic browser
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
        ]
        
        # Common API endpoints to check
        self.api_endpoints = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/api/v3',
            '/rest',
            '/rest/v1',
            '/rest/v2',
            '/graphql',
            '/query',
            '/service',
            '/services',
            '/swagger',
            '/swagger-ui',
            '/swagger-ui.html',
            '/swagger/index.html',
            '/api-docs',
            '/api/docs',
            '/openapi',
            '/openapi.json',
            '/spec',
            '/specs',
            '/redoc',
            '/api/swagger',
            '/api/swagger-ui',
            '/api/swagger-ui.html',
            '/api/api-docs'
        ]
        
        # Common API documentation formats
        self.api_doc_patterns = [
            r'"swagger":\s*"[0-9]',
            r'"openapi":\s*"[0-9]',
            r'<title>.*Swagger UI.*</title>',
            r'<title>.*API.?Doc.*</title>',
            r'<title>.*ReDoc.*</title>'
        ]
        
        self.session = requests.Session()
    
    def scan(self, url, api_key=None):
        """
        Scan the given URL for API security vulnerabilities
        
        Args:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
        
        Returns:
            list: Found API vulnerabilities details
        """
        logger.info(f"Starting API scan on {url}")
        vulnerabilities = []
        
        try:
            # Discover API endpoints
            api_endpoints = self._discover_api_endpoints(url)
            
            if not api_endpoints:
                self._log_verbose("No API endpoints discovered")
                return vulnerabilities
            
            self._log_verbose(f"Discovered {len(api_endpoints)} potential API endpoints")
            
            # Check each endpoint for vulnerabilities
            for endpoint in api_endpoints:
                self._log_verbose(f"Checking API endpoint: {endpoint}")
                
                # Check for exposed API documentation
                doc_vulns = self._check_exposed_api_docs(endpoint)
                vulnerabilities.extend(doc_vulns)
                
                # Check for missing authentication
                auth_vulns = self._check_missing_authentication(endpoint)
                vulnerabilities.extend(auth_vulns)
                
                # Check for excessive data exposure
                data_vulns = self._check_excessive_data_exposure(endpoint)
                vulnerabilities.extend(data_vulns)
                
                # Check for lack of rate limiting
                rate_vulns = self._check_rate_limiting(endpoint)
                vulnerabilities.extend(rate_vulns)
            
            # Use API for enhanced scanning if available
            if api_key:
                self._log_verbose("Using API for enhanced API security scanning")
                api_vulns = self._api_enhanced_scan(url, api_key)
                vulnerabilities.extend(api_vulns)
            
            logger.info(f"API scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except requests.RequestException as e:
            logger.error(f"Request error during API scan: {str(e)}")
            print(f"{Fore.RED}[!] Error during API scan: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _discover_api_endpoints(self, url):
        """
        Discover API endpoints on the target
        
        Args:
            url (str): Base URL
        
        Returns:
            list: Discovered API endpoints
        """
        discovered_endpoints = []
        
        # Ensure URL ends with a slash
        if not url.endswith('/'):
            base_url = url + '/'
        else:
            base_url = url
        
        # Check common API endpoints
        for endpoint in self.api_endpoints:
            full_url = urljoin(base_url, endpoint)
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                response = self.session.get(
                    full_url, 
                    headers=headers, 
                    timeout=self.timeout,
                    verify=True
                )
                
                # If we get a 2XX or 3XX response, it might be an API endpoint
                if 200 <= response.status_code < 400:
                    discovered_endpoints.append(full_url)
                    self._log_verbose(f"Discovered API endpoint: {full_url} ({response.status_code})")
                    
                    # Check if it's JSON response
                    content_type = response.headers.get('Content-Type', '')
                    if 'application/json' in content_type:
                        self._log_verbose(f"Endpoint returns JSON: {full_url}")
                        
            except requests.RequestException:
                # Skip this endpoint on error
                continue
        
        return discovered_endpoints
    
    def _check_exposed_api_docs(self, url):
        """
        Check for exposed API documentation
        
        Args:
            url (str): API endpoint URL
        
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = self.session.get(
                url, 
                headers=headers, 
                timeout=self.timeout,
                verify=True
            )
            
            # Check if response contains API documentation
            for pattern in self.api_doc_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    self._log_verbose(f"Found exposed API documentation at {url}")
                    vulnerabilities.append({
                        'type': 'API',
                        'subtype': 'Exposed Documentation',
                        'endpoint': url,
                        'severity': 'Medium',
                        'confidence': 'High',
                        'description': 'API documentation is publicly accessible'
                    })
                    break
                    
        except requests.RequestException:
            # Skip this check on error
            pass
        
        return vulnerabilities
    
    def _check_missing_authentication(self, url):
        """
        Check for missing authentication in API
        
        Args:
            url (str): API endpoint URL
        
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Try to access the API without authentication
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = self.session.get(
                url, 
                headers=headers, 
                timeout=self.timeout,
                verify=True
            )
            
            # If we get a 200 OK and JSON response, it might be missing authentication
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                if 'application/json' in content_type:
                    try:
                        # Try to parse as JSON
                        json_data = response.json()
                        
                        # If it contains data, it might be missing authentication
                        if json_data and not isinstance(json_data, str):
                            self._log_verbose(f"API endpoint may lack authentication: {url}")
                            vulnerabilities.append({
                                'type': 'API',
                                'subtype': 'Missing Authentication',
                                'endpoint': url,
                                'severity': 'High',
                                'confidence': 'Medium',
                                'description': 'API endpoint returns data without authentication'
                            })
                    except json.JSONDecodeError:
                        # Not JSON data
                        pass
                    
        except requests.RequestException:
            # Skip this check on error
            pass
        
        return vulnerabilities
    
    def _check_excessive_data_exposure(self, url):
        """
        Check for excessive data exposure in API
        
        Args:
            url (str): API endpoint URL
        
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = self.session.get(
                url, 
                headers=headers, 
                timeout=self.timeout,
                verify=True
            )
            
            # Check if response contains sensitive data patterns
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                try:
                    json_data = response.json()
                    
                    # Check for sensitive data patterns in JSON
                    sensitive_fields = self._check_sensitive_data(json_data)
                    
                    if sensitive_fields:
                        self._log_verbose(f"API endpoint may expose sensitive data: {url}")
                        vulnerabilities.append({
                            'type': 'API',
                            'subtype': 'Excessive Data Exposure',
                            'endpoint': url,
                            'fields': sensitive_fields,
                            'severity': 'High',
                            'confidence': 'Medium',
                            'description': f'API endpoint exposes potentially sensitive data: {", ".join(sensitive_fields)}'
                        })
                except json.JSONDecodeError:
                    # Not JSON data
                    pass
                    
        except requests.RequestException:
            # Skip this check on error
            pass
        
        return vulnerabilities
    
    def _check_sensitive_data(self, data, parent_key=''):
        """
        Check for sensitive data in JSON response
        
        Args:
            data: JSON data to check
            parent_key (str): Parent key for nested data
        
        Returns:
            list: Sensitive field names found
        """
        sensitive_fields = []
        sensitive_patterns = [
            'password', 'passwd', 'secret', 'token', 'api_key', 'apikey', 'auth',
            'credential', 'ssh_key', 'private_key', 'secret_key', 'access_key',
            'credit_card', 'card', 'ssn', 'social', 'tax', 'account', 'routing',
            'address', 'email', 'phone', 'mobile', 'dob', 'birth', 'salary'
        ]
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_key = f"{parent_key}.{key}" if parent_key else key
                
                # Check if key matches sensitive patterns
                if any(pattern in key.lower() for pattern in sensitive_patterns):
                    sensitive_fields.append(current_key)
                
                # Recursively check nested data
                if isinstance(value, (dict, list)):
                    nested_fields = self._check_sensitive_data(value, current_key)
                    sensitive_fields.extend(nested_fields)
                    
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_key = f"{parent_key}[{i}]"
                
                # Recursively check nested data
                if isinstance(item, (dict, list)):
                    nested_fields = self._check_sensitive_data(item, current_key)
                    sensitive_fields.extend(nested_fields)
        
        return sensitive_fields
    
    def _check_rate_limiting(self, url):
        """
        Check for lack of rate limiting in API
        
        Args:
            url (str): API endpoint URL
        
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        
        # Make multiple requests to check for rate limiting
        rate_limit_headers = [
            'X-Rate-Limit',
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'Retry-After',
            'RateLimit-Limit',
            'RateLimit-Remaining',
            'RateLimit-Reset'
        ]
        
        try:
            has_rate_limiting = False
            
            # Make 5 quick requests to trigger rate limiting
            for i in range(5):
                headers = {'User-Agent': random.choice(self.user_agents)}
                response = self.session.get(
                    url, 
                    headers=headers, 
                    timeout=self.timeout,
                    verify=True
                )
                
                # Check for rate limiting headers
                for header in rate_limit_headers:
                    if header.lower() in [h.lower() for h in response.headers]:
                        has_rate_limiting = True
                        break
                
                # Check if we got a 429 Too Many Requests
                if response.status_code == 429:
                    has_rate_limiting = True
                    break
                
                if has_rate_limiting:
                    break
            
            if not has_rate_limiting:
                self._log_verbose(f"API endpoint may lack rate limiting: {url}")
                vulnerabilities.append({
                    'type': 'API',
                    'subtype': 'Missing Rate Limiting',
                    'endpoint': url,
                    'severity': 'Medium',
                    'confidence': 'Low',
                    'description': 'API endpoint does not implement rate limiting'
                })
                    
        except requests.RequestException:
            # Skip this check on error
            pass
        
        return vulnerabilities
    
    def _api_enhanced_scan(self, url, api_key):
        """
        Use API for enhanced API security scanning (placeholder for actual API integration)
        
        Args:
            url (str): Target URL
            api_key (str): API key for authentication
        
        Returns:
            list: Additional vulnerabilities found via API
        """
        # This is a placeholder for actual API integration
        # In a real implementation, you would call a security API service
        self._log_verbose("API enhanced scanning is a placeholder in this version")
        return []
    
    def _log_verbose(self, message):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            logger.debug(message)
            print(f"{Fore.CYAN}[API] {message}{Style.RESET_ALL}")
