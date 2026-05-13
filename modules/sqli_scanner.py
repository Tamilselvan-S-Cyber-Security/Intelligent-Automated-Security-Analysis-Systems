"""
SQL Injection vulnerability scanner module
"""

import re
import logging
import random
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from colorama import Fore, Style

logger = logging.getLogger('CyberWolf.SQLiScanner')

class SQLiScanner:
    """
    Scanner module for detecting SQL Injection vulnerabilities
    """
    
    def __init__(self, timeout=10, verbose=False):
        """
        Initialize the SQL Injection scanner
        
        Args:
            timeout (int): Request timeout in seconds
            verbose (bool): Enable verbose output
        """
        self.timeout = timeout
        self.verbose = verbose
        
        # SQL Injection payloads to test with
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "\' OR 1=1 #",
            "\" OR \"\"=\"",
            "\" OR 1=1 --",
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT null,null,null --",
            "admin' --",
            "'; WAITFOR DELAY '0:0:5' --",
            "1' AND (SELECT 1 FROM (SELECT SLEEP(5))A) --"
        ]
        
        # Error messages that might indicate SQL injection vulnerability
        self.error_patterns = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysqli?",
            r"PostgreSQL.*?ERROR",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Microsoft SQL Server",
            r"SQLite3::query",
            r"SQLITE_ERROR",
            r"DB2 SQL error",
            r"quoted string not properly terminated",
            r"unclosed quotation mark after the character string",
            r"you have an error in your sql syntax"
        ]
        
        # User agent to mimic browser
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
        ]
        
        self.session = requests.Session()
    
    def scan(self, url, api_key=None):
        """
        Scan the given URL for SQL Injection vulnerabilities
        
        Args:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
        
        Returns:
            list: Found SQL Injection vulnerabilities details
        """
        logger.info(f"Starting SQL Injection scan on {url}")
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
            
            # Check URL parameters for SQL Injection vulnerabilities
            if url_params:
                self._log_verbose(f"Found {len(url_params)} URL parameters to test")
                for param in url_params:
                    param_vulns = self._check_param_sqli(url, param)
                    vulnerabilities.extend(param_vulns)
            
            # Check forms for SQL Injection vulnerabilities
            if forms:
                self._log_verbose(f"Found {len(forms)} forms to test")
                for form_idx, form in enumerate(forms):
                    form_vulns = self._check_form_sqli(url, form, form_idx)
                    vulnerabilities.extend(form_vulns)
            
            # Use API for enhanced scanning if available
            if api_key:
                self._log_verbose("Using API for enhanced SQL Injection scanning")
                api_vulns = self._api_enhanced_scan(url, api_key)
                vulnerabilities.extend(api_vulns)
            
            logger.info(f"SQL Injection scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except requests.RequestException as e:
            logger.error(f"Request error during SQL Injection scan: {str(e)}")
            print(f"{Fore.RED}[!] Error during SQL Injection scan: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _check_param_sqli(self, url, param):
        """
        Check URL parameter for SQL Injection vulnerabilities
        
        Args:
            url (str): Target URL
            param (str): Parameter name to check
        
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        # Get the original response to compare with
        original_response = self._get_response(url)
        if not original_response:
            return vulnerabilities
        
        # Test the specified parameter with each payload
        for payload in self.sqli_payloads:
            # Create a new set of parameters with the payload
            test_params = params.copy()
            test_params[param] = [payload]
            
            # Build the new query string
            new_query = "&".join([f"{p}={v[0]}" for p, v in test_params.items()])
            
            # Construct the test URL
            test_url = urlparse(url)._replace(query=new_query).geturl()
            
            # Test the URL for SQL Injection
            is_vulnerable, error_type = self._is_vulnerable_to_sqli(test_url, original_response)
            
            if is_vulnerable:
                self._log_verbose(f"Found SQL Injection vulnerability in parameter {param}")
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'method': 'GET',
                    'location': 'URL Parameter',
                    'param': param,
                    'payload': payload,
                    'error_type': error_type,
                    'url': test_url
                })
        
        return vulnerabilities
    
    def _check_form_sqli(self, url, form, form_idx):
        """
        Check form for SQL Injection vulnerabilities
        
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
        
        # Get the original response to compare with
        if method == 'GET':
            # For GET forms, we need the base response without parameters
            original_response = self._get_response(form_url)
        else:
            # For POST forms, we need a response with default form values
            form_data = self._create_form_data(inputs)
            original_response = self._post_response(form_url, form_data)
        
        if not original_response:
            return vulnerabilities
        
        for payload in self.sqli_payloads:
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
                
                # Test the form for SQL Injection
                response = None
                try:
                    if method == 'GET':
                        test_url = f"{form_url}?{self._form_data_to_query(form_data)}"
                        is_vulnerable, error_type = self._is_vulnerable_to_sqli(test_url, original_response)
                    else:  # POST
                        response = self.session.post(
                            form_url, 
                            data=form_data, 
                            headers={'User-Agent': random.choice(self.user_agents)},
                            timeout=self.timeout
                        )
                        is_vulnerable, error_type = self._check_response_for_sqli(response, original_response)
                
                except requests.RequestException:
                    continue
                
                if is_vulnerable:
                    self._log_verbose(f"Found SQL Injection vulnerability in form field {input_name}")
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'method': method,
                        'location': f'Form #{form_idx+1} - Field: {input_name}',
                        'param': input_name,
                        'payload': payload,
                        'error_type': error_type,
                        'url': form_url
                    })
        
        return vulnerabilities
    
    def _create_form_data(self, inputs, target_name=None, payload=None):
        """
        Create form data with optional payload in a target field
        
        Args:
            inputs (list): Form input fields
            target_name (str, optional): Name of the target field
            payload (str, optional): SQL Injection payload
        
        Returns:
            dict: Form data
        """
        form_data = {}
        
        for input_field in inputs:
            name = input_field.get('name', '')
            if not name:
                continue
                
            # If this is our target field and we have a payload, use it
            if name == target_name and payload:
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
    
    def _form_data_to_query(self, form_data):
        """Convert form data to query string"""
        return "&".join([f"{k}={v}" for k, v in form_data.items()])
    
    def _get_response(self, url):
        """Get response from URL with error handling"""
        try:
            return self.session.get(
                url, 
                headers={'User-Agent': random.choice(self.user_agents)}, 
                timeout=self.timeout
            )
        except requests.RequestException:
            return None
    
    def _post_response(self, url, data):
        """Post data to URL with error handling"""
        try:
            return self.session.post(
                url, 
                data=data,
                headers={'User-Agent': random.choice(self.user_agents)}, 
                timeout=self.timeout
            )
        except requests.RequestException:
            return None
    
    def _is_vulnerable_to_sqli(self, url, original_response):
        """
        Check if a URL is vulnerable to SQL Injection
        
        Args:
            url (str): URL to check
            original_response (Response): Original response for comparison
        
        Returns:
            tuple: (is_vulnerable, error_type)
        """
        response = self._get_response(url)
        if not response:
            return False, None
        
        return self._check_response_for_sqli(response, original_response)
    
    def _check_response_for_sqli(self, response, original_response):
        """
        Check if response indicates SQL Injection vulnerability
        
        Args:
            response (Response): Response to check
            original_response (Response): Original response for comparison
        
        Returns:
            tuple: (is_vulnerable, error_type)
        """
        # Check for error-based SQLi
        for pattern in self.error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True, 'Error-based'
        
        # Check for significant changes in response content
        # This may indicate boolean-based or union-based SQLi
        if original_response and len(original_response.text) > 0:
            length_diff = abs(len(response.text) - len(original_response.text))
            if length_diff > 100 and length_diff / len(original_response.text) > 0.25:
                return True, 'Content-based'
        
        # Check for time-based SQLi (would require more sophisticated timing checks)
        # This is a simplified placeholder
        if response.elapsed.total_seconds() > self.timeout * 0.8:
            return True, 'Time-based'
        
        return False, None
    
    def _api_enhanced_scan(self, url, api_key):
        """
        Use API for enhanced SQL Injection scanning
        
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
            print(f"{Fore.CYAN}[SQLi] {message}{Style.RESET_ALL}")
