"""
Cross-Site Request Forgery (CSRF) vulnerability scanner module
"""

import re
import logging
import random
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style

logger = logging.getLogger('CyberWolf.CSRFScanner')

class CSRFScanner:
    """
    Scanner module for detecting Cross-Site Request Forgery vulnerabilities
    """
    
    def __init__(self, timeout=10, verbose=False):
        """
        Initialize the CSRF scanner
        
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
        
        # Common CSRF token names
        self.csrf_token_names = [
            'csrf', 'csrf_token', 'csrftoken', 'xsrf', 'xsrf_token', 
            'anti-csrf', 'anti-xsrf', '_csrf', '_xsrf', '__csrf_token',
            'token', 'authenticity_token', '_token', 'csrf-token', 'xsrf-token'
        ]
        
        self.session = requests.Session()
    
    def scan(self, url, api_key=None):
        """
        Scan the given URL for CSRF vulnerabilities
        
        Args:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
        
        Returns:
            list: Found CSRF vulnerabilities details
        """
        logger.info(f"Starting CSRF scan on {url}")
        vulnerabilities = []
        
        try:
            # Get random user agent
            headers = {'User-Agent': random.choice(self.user_agents)}
            
            # First, get the page to find forms
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
            
            # Check forms for CSRF vulnerabilities
            if forms:
                self._log_verbose(f"Found {len(forms)} forms to test")
                for form_idx, form in enumerate(forms):
                    form_vulns = self._check_form_csrf(url, form, form_idx)
                    vulnerabilities.extend(form_vulns)
            
            # Use API for enhanced scanning if available
            if api_key:
                self._log_verbose("Using API for enhanced CSRF scanning")
                api_vulns = self._api_enhanced_scan(url, api_key)
                vulnerabilities.extend(api_vulns)
            
            logger.info(f"CSRF scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except requests.RequestException as e:
            logger.error(f"Request error during CSRF scan: {str(e)}")
            print(f"{Fore.RED}[!] Error during CSRF scan: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _check_form_csrf(self, url, form, form_idx):
        """
        Check form for CSRF vulnerabilities
        
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
        
        # Skip GET forms as they're not typically vulnerable to CSRF
        if method == 'GET':
            return []
        
        # Construct the form submission URL
        form_url = url if not action else urljoin(url, action)
        
        # Check if the form has a CSRF token
        has_csrf_token = False
        csrf_token_field = None
        
        # Check hidden inputs for CSRF tokens
        hidden_inputs = form.find_all('input', {'type': 'hidden'})
        for hidden_input in hidden_inputs:
            input_name = hidden_input.get('name', '').lower()
            if any(token_name in input_name for token_name in self.csrf_token_names):
                has_csrf_token = True
                csrf_token_field = hidden_input.get('name')
                break
        
        # Check for CSRF meta tags
        if not has_csrf_token:
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                if meta.get('name', '').lower() in self.csrf_token_names or meta.get('name', '').lower() == 'csrf-param':
                    has_csrf_token = True
                    break
        
        # If no CSRF token found, the form might be vulnerable
        if not has_csrf_token and method == 'POST':
            self._log_verbose(f"Found potential CSRF vulnerability in form #{form_idx+1}")
            vulnerabilities.append({
                'type': 'CSRF',
                'method': method,
                'location': f'Form #{form_idx+1}',
                'form_action': form_url,
                'has_csrf_token': False,
                'severity': 'High',
                'confidence': 'Medium',
                'description': 'Form does not contain a CSRF token'
            })
        
        return vulnerabilities
    
    def _api_enhanced_scan(self, url, api_key):
        """
        Use API for enhanced CSRF scanning (placeholder for actual API integration)
        
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
            print(f"{Fore.CYAN}[CSRF] {message}{Style.RESET_ALL}")
