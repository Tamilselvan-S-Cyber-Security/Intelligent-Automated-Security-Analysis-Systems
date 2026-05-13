"""
Cross-Site Scripting (XSS) vulnerability scanner module
"""

import re
import logging
import random
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from colorama import Fore, Style

logger = logging.getLogger('CyberWolf.XSSScanner')

class XSSScanner:
    """
    Scanner module for detecting Cross-Site Scripting vulnerabilities
    """
    
    def __init__(self, timeout=10, verbose=False):
        """
        Initialize the XSS scanner
        
        Args:
            timeout (int): Request timeout in seconds
            verbose (bool): Enable verbose output
        """
        self.timeout = timeout
        self.verbose = verbose
        
        # XSS payloads to test with
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "';alert('XSS');//",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "<body onload=alert('XSS')>",
            "<svg/onload=alert('XSS')>"
        ]
        
        # User agent to mimic browser
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
        ]
        
        self.session = requests.Session()
    
    def scan(self, url, api_key=None):
        """
        Scan the given URL for XSS vulnerabilities
        
        Args:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
        
        Returns:
            list: Found XSS vulnerabilities details
        """
        logger.info(f"Starting XSS scan on {url}")
        vulnerabilities = []
        
        try:
            # Get random user agent
            headers = {'User-Agent': random.choice(self.user_agents)}
            
            # First, get the page to find forms and parameters
            response = self.session.get(
                url, 
                headers=headers, 
                timeout=self.timeout,
                verify=True
            )
            response.raise_for_status()
            
            # Extract forms from the page
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            # Analyze URL parameters
            url_params = parse_qs(urlparse(url).query)
            
            # Check URL parameters for XSS vulnerabilities
            if url_params:
                self._log_verbose(f"Found {len(url_params)} URL parameters to test")
                for param in url_params:
                    param_vulns = self._check_param_xss(url, param)
                    vulnerabilities.extend(param_vulns)
            
            # Check forms for XSS vulnerabilities
            if forms:
                self._log_verbose(f"Found {len(forms)} forms to test")
                for form_idx, form in enumerate(forms):
                    form_vulns = self._check_form_xss(url, form, form_idx)
                    vulnerabilities.extend(form_vulns)
            
            # Use API for enhanced scanning if available
            if api_key:
                self._log_verbose("Using API for enhanced XSS scanning")
                api_vulns = self._api_enhanced_scan(url, api_key)
                vulnerabilities.extend(api_vulns)
            
            logger.info(f"XSS scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except requests.RequestException as e:
            logger.error(f"Request error during XSS scan: {str(e)}")
            print(f"{Fore.RED}[!] Error during XSS scan: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _check_param_xss(self, url, param):
        """
        Check URL parameter for XSS vulnerabilities
        
        Args:
            url (str): Target URL
            param (str): Parameter name to check
        
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        # Test only the specified parameter with each payload
        for payload in self.xss_payloads:
            # Create a new set of parameters with the payload
            test_params = params.copy()
            test_params[param] = [payload]
            
            # Build the new query string
            new_query = "&".join([f"{p}={v[0]}" for p, v in test_params.items()])
            
            # Construct the test URL
            test_url = urlparse(url)._replace(query=new_query).geturl()
            
            # Check if the URL is vulnerable
            if self._is_vulnerable_to_xss(test_url, payload):
                self._log_verbose(f"Found XSS vulnerability in parameter {param}")
                vulnerabilities.append({
                    'type': 'XSS',
                    'method': 'GET',
                    'location': 'URL Parameter',
                    'param': param,
                    'payload': payload,
                    'url': test_url
                })
        
        return vulnerabilities
    
    def _check_form_xss(self, url, form, form_idx):
        """
        Check form for XSS vulnerabilities
        
        Args:
            url (str): Base URL
            form (BeautifulSoup): Form element to check
            form_idx (int): Form index for identification
        
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        
        # Get form attributes
        action = form.get('action', '')
        method = form.get('method', 'get').upper()
        
        # Construct the form submission URL
        form_url = url if not action else urljoin(url, action)
        
        # Get all input fields
        inputs = form.find_all(['input', 'textarea', 'select'])
        
        for payload in self.xss_payloads:
            for input_field in inputs:
                # Skip submit and button types
                input_type = input_field.get('type', '').lower()
                if input_type in ['submit', 'button', 'image', 'reset', 'file', 'checkbox', 'radio']:
                    continue
                
                # Get the input name
                input_name = input_field.get('name', '')
                if not input_name:
                    continue
                
                # Create form data with payload
                form_data = self._create_form_data(inputs, input_name, payload)
                
                # Check if the form is vulnerable
                is_vulnerable = False
                try:
                    if method == 'GET':
                        response = self.session.get(
                            form_url, 
                            params=form_data, 
                            timeout=self.timeout
                        )
                    else:  # POST
                        response = self.session.post(
                            form_url, 
                            data=form_data, 
                            timeout=self.timeout
                        )
                    
                    # Check if the payload is reflected in the response
                    if payload in response.text:
                        is_vulnerable = True
                        
                except requests.RequestException:
                    # Skip this test case on error
                    continue
                
                if is_vulnerable:
                    self._log_verbose(f"Found XSS vulnerability in form field {input_name}")
                    vulnerabilities.append({
                        'type': 'XSS',
                        'method': method,
                        'location': f'Form #{form_idx+1} - Field: {input_name}',
                        'param': input_name,
                        'payload': payload,
                        'url': form_url
                    })
        
        return vulnerabilities
    
    def _create_form_data(self, inputs, target_name, payload):
        """
        Create form data with payload in the target field
        
        Args:
            inputs (list): Form input fields
            target_name (str): Name of the target field
            payload (str): XSS payload
        
        Returns:
            dict: Form data with payload
        """
        form_data = {}
        
        for input_field in inputs:
            name = input_field.get('name', '')
            if not name:
                continue
                
            # If this is our target field, use the payload
            if name == target_name:
                form_data[name] = payload
            else:
                # For other fields, use default values based on type
                input_type = input_field.get('type', 'text').lower()
                if input_type == 'email':
                    form_data[name] = 'test@example.com'
                elif input_type == 'number':
                    form_data[name] = '1'
                elif input_type in ['checkbox', 'radio']:
                    # Only add if the field is checked/selected
                    if input_field.get('checked'):
                        form_data[name] = input_field.get('value', 'on')
                else:
                    # Use the default value if available
                    form_data[name] = input_field.get('value', 'test')
        
        return form_data
    
    def _is_vulnerable_to_xss(self, url, payload):
        """
        Check if a URL is vulnerable to XSS
        
        Args:
            url (str): URL to check
            payload (str): XSS payload used
        
        Returns:
            bool: True if vulnerable, False otherwise
        """
        try:
            response = self.session.get(
                url, 
                headers={'User-Agent': random.choice(self.user_agents)}, 
                timeout=self.timeout
            )
            # Check if the payload is reflected in the response
            return payload in response.text
        except requests.RequestException:
            return False
    
    def _api_enhanced_scan(self, url, api_key):
        """
        Use API for enhanced XSS scanning (placeholder for actual API integration)
        
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
            print(f"{Fore.CYAN}[XSS] {message}{Style.RESET_ALL}")
