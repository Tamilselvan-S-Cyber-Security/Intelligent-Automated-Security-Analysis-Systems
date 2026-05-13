"""
Brute Force vulnerability scanner module
"""

import re
import logging
import random
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style

logger = logging.getLogger('CyberWolf.BruteForceScanner')

class BruteForceScanner:
    """
    Scanner module for detecting vulnerabilities to brute force attacks
    """
    
    def __init__(self, timeout=10, verbose=False):
        """
        Initialize the brute force scanner
        
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
        
        # Common login page paths
        self.login_paths = [
            '/login',
            '/signin',
            '/auth',
            '/authenticate',
            '/user/login',
            '/account/login',
            '/admin/login',
            '/administrator',
            '/wp-login.php',
            '/user/signin',
            '/portal',
            '/dashboard',
            '/member/login',
            '/membership/login',
            '/customer/login',
            '/client/login',
            '/panel',
            '/cp',
            '/cpanel'
        ]
        
        # Common username and password fields
        self.username_fields = [
            'username', 'user', 'email', 'login', 'name', 'id', 'userid',
            'user_id', 'user_name', 'user-name', 'user_email', 'user-email',
            'account', 'accountname'
        ]
        
        self.password_fields = [
            'password', 'pass', 'passwd', 'pwd', 'secret', 'user_password',
            'user-password', 'user_pass', 'user-pass', 'passcode'
        ]
        
        # Test credentials
        self.test_credentials = [
            {'username': 'test', 'password': 'test'},
            {'username': 'admin', 'password': 'admin'},
            {'username': 'user', 'password': 'password'},
            {'username': 'guest', 'password': 'guest'}
        ]
        
        self.session = requests.Session()
    
    def scan(self, url, api_key=None):
        """
        Scan the given URL for brute force vulnerabilities
        
        Args:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
        
        Returns:
            list: Found brute force vulnerabilities details
        """
        logger.info(f"Starting brute force vulnerability scan on {url}")
        vulnerabilities = []
        
        try:
            # Find login pages
            login_pages = self._find_login_pages(url)
            
            if not login_pages:
                self._log_verbose("No login pages found")
                return vulnerabilities
            
            self._log_verbose(f"Found {len(login_pages)} potential login pages")
            
            # Check each login page for vulnerabilities
            for login_page in login_pages:
                self._log_verbose(f"Checking login page: {login_page}")
                
                # Check for account lockout
                lockout_vulns = self._check_account_lockout(login_page)
                vulnerabilities.extend(lockout_vulns)
                
                # Check for CAPTCHA or other anti-automation
                captcha_vulns = self._check_missing_captcha(login_page)
                vulnerabilities.extend(captcha_vulns)
                
                # Check for rate limiting
                rate_vulns = self._check_rate_limiting(login_page)
                vulnerabilities.extend(rate_vulns)
            
            # Use API for enhanced scanning if available
            if api_key:
                self._log_verbose("Using API for enhanced brute force scanning")
                api_vulns = self._api_enhanced_scan(url, api_key)
                vulnerabilities.extend(api_vulns)
            
            logger.info(f"Brute force scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except requests.RequestException as e:
            logger.error(f"Request error during brute force scan: {str(e)}")
            print(f"{Fore.RED}[!] Error during brute force scan: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _find_login_pages(self, url):
        """
        Find login pages on the target
        
        Args:
            url (str): Base URL
        
        Returns:
            list: Discovered login pages
        """
        login_pages = []
        
        # Ensure URL ends with a slash
        if not url.endswith('/'):
            base_url = url + '/'
        else:
            base_url = url
        
        # Check common login paths
        for path in self.login_paths:
            login_url = urljoin(base_url, path)
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                response = self.session.get(
                    login_url, 
                    headers=headers, 
                    timeout=self.timeout,
                    verify=True
                )
                
                # If we get a 2XX response, it might be a login page
                if 200 <= response.status_code < 300:
                    # Check if it has login form elements
                    if self._is_login_page(response.text):
                        login_pages.append(login_url)
                        self._log_verbose(f"Found login page: {login_url}")
                    
            except requests.RequestException:
                # Skip this path on error
                continue
        
        return login_pages
    
    def _is_login_page(self, html_content):
        """
        Check if a page is a login page
        
        Args:
            html_content (str): HTML content to check
        
        Returns:
            bool: True if it's a login page, False otherwise
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Check for login-related keywords in title or headers
            title = soup.title.text.lower() if soup.title else ''
            headers = [h.text.lower() for h in soup.find_all(['h1', 'h2', 'h3'])]
            
            login_keywords = ['login', 'sign in', 'signin', 'log in', 'authenticate', 'authentication']
            if any(keyword in title for keyword in login_keywords) or \
               any(any(keyword in h for keyword in login_keywords) for h in headers):
                return True
            
            # Check for login form
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                input_names = [i.get('name', '').lower() for i in inputs]
                input_types = [i.get('type', '').lower() for i in inputs]
                
                # Check if form has username and password fields
                has_username = any(name in self.username_fields for name in input_names)
                has_password = any(name in self.password_fields for name in input_names) or 'password' in input_types
                
                if has_username and has_password:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking if page is a login page: {str(e)}")
            return False
    
    def _check_account_lockout(self, login_url):
        """
        Check if the login page implements account lockout
        
        Args:
            login_url (str): Login page URL
        
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Get the login form
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = self.session.get(
                login_url, 
                headers=headers, 
                timeout=self.timeout,
                verify=True
            )
            
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                return vulnerabilities
            
            # Find the login form
            login_form = None
            for form in forms:
                inputs = form.find_all('input')
                input_names = [i.get('name', '').lower() for i in inputs]
                input_types = [i.get('type', '').lower() for i in inputs]
                
                has_username = any(name in self.username_fields for name in input_names)
                has_password = any(name in self.password_fields for name in input_names) or 'password' in input_types
                
                if has_username and has_password:
                    login_form = form
                    break
            
            if not login_form:
                return vulnerabilities
            
            # Extract form details
            form_action = login_form.get('action', '')
            form_method = login_form.get('method', 'post').lower()
            
            # Construct the form submission URL
            form_url = login_url if not form_action else urljoin(login_url, form_action)
            
            # Find username and password field names
            inputs = login_form.find_all('input')
            username_field = None
            password_field = None
            
            for input_field in inputs:
                input_name = input_field.get('name', '').lower()
                input_type = input_field.get('type', '').lower()
                
                if not username_field and (input_name in self.username_fields or input_type == 'email'):
                    username_field = input_field.get('name')
                
                if not password_field and (input_name in self.password_fields or input_type == 'password'):
                    password_field = input_field.get('name')
            
            if not username_field or not password_field:
                return vulnerabilities
            
            # Try multiple failed login attempts with the same username
            lockout_detected = False
            
            # Use a consistent username but different passwords
            test_username = 'testuser_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=5))
            
            for i in range(5):
                form_data = {
                    username_field: test_username,
                    password_field: f'wrong_password_{i}'
                }
                
                # Add other form fields with default values
                for input_field in inputs:
                    field_name = input_field.get('name')
                    if field_name and field_name != username_field and field_name != password_field:
                        field_type = input_field.get('type', '').lower()
                        if field_type not in ['submit', 'button', 'image', 'reset']:
                            form_data[field_name] = input_field.get('value', '')
                
                # Submit the form
                if form_method == 'post':
                    response = self.session.post(
                        form_url,
                        data=form_data,
                        headers=headers,
                        timeout=self.timeout,
                        allow_redirects=True
                    )
                else:
                    response = self.session.get(
                        form_url,
                        params=form_data,
                        headers=headers,
                        timeout=self.timeout,
                        allow_redirects=True
                    )
                
                # Check for lockout indicators
                lockout_keywords = [
                    'account locked', 'too many attempts', 'temporarily disabled',
                    'account disabled', 'try again later', 'locked out',
                    'maximum attempts', 'account blocked', 'security measure'
                ]
                
                if any(keyword in response.text.lower() for keyword in lockout_keywords):
                    lockout_detected = True
                    break
                
                # If we get a different status code (like 403), it might indicate lockout
                if i > 0 and response.status_code != 200:
                    lockout_detected = True
                    break
            
            if not lockout_detected:
                self._log_verbose(f"No account lockout detected on {login_url}")
                vulnerabilities.append({
                    'type': 'Brute Force',
                    'subtype': 'Missing Account Lockout',
                    'url': login_url,
                    'severity': 'High',
                    'confidence': 'Medium',
                    'description': 'Login page does not implement account lockout after multiple failed attempts'
                })
            
        except Exception as e:
            logger.error(f"Error checking account lockout: {str(e)}")
        
        return vulnerabilities
    
    def _check_missing_captcha(self, login_url):
        """
        Check if the login page implements CAPTCHA or other anti-automation
        
        Args:
            login_url (str): Login page URL
        
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Get the login page
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = self.session.get(
                login_url, 
                headers=headers, 
                timeout=self.timeout,
                verify=True
            )
            
            # Check for CAPTCHA indicators
            captcha_indicators = [
                'captcha', 'recaptcha', 'g-recaptcha', 'h-captcha', 'hcaptcha',
                'cf-turnstile', 'turnstile', 'solvemedia', 'botdetect'
            ]
            
            has_captcha = False
            
            # Check in HTML
            for indicator in captcha_indicators:
                if indicator in response.text.lower():
                    has_captcha = True
                    break
            
            # Check for CAPTCHA-related scripts
            if not has_captcha:
                soup = BeautifulSoup(response.text, 'html.parser')
                scripts = soup.find_all('script')
                
                for script in scripts:
                    src = script.get('src', '')
                    if src and any(indicator in src.lower() for indicator in captcha_indicators):
                        has_captcha = True
                        break
                    
                    script_content = script.string or ''
                    if any(indicator in script_content.lower() for indicator in captcha_indicators):
                        has_captcha = True
                        break
            
            if not has_captcha:
                self._log_verbose(f"No CAPTCHA detected on {login_url}")
                vulnerabilities.append({
                    'type': 'Brute Force',
                    'subtype': 'Missing CAPTCHA',
                    'url': login_url,
                    'severity': 'Medium',
                    'confidence': 'Medium',
                    'description': 'Login page does not implement CAPTCHA or other anti-automation measures'
                })
            
        except Exception as e:
            logger.error(f"Error checking for CAPTCHA: {str(e)}")
        
        return vulnerabilities
    
    def _check_rate_limiting(self, login_url):
        """
        Check if the login page implements rate limiting
        
        Args:
            login_url (str): Login page URL
        
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        
        # This is a simplified check - in a real scanner, you would need more sophisticated methods
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
            
            # Make multiple quick requests to trigger rate limiting
            for i in range(5):
                headers = {'User-Agent': random.choice(self.user_agents)}
                response = self.session.get(
                    login_url, 
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
                self._log_verbose(f"No rate limiting detected on {login_url}")
                vulnerabilities.append({
                    'type': 'Brute Force',
                    'subtype': 'Missing Rate Limiting',
                    'url': login_url,
                    'severity': 'Medium',
                    'confidence': 'Low',
                    'description': 'Login page does not implement rate limiting'
                })
                    
        except Exception as e:
            logger.error(f"Error checking rate limiting: {str(e)}")
        
        return vulnerabilities
    
    def _api_enhanced_scan(self, url, api_key):
        """
        Use API for enhanced brute force scanning (placeholder for actual API integration)
        
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
            print(f"{Fore.CYAN}[Brute Force] {message}{Style.RESET_ALL}")
