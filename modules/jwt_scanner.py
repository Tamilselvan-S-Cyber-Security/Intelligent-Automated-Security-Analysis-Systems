"""
JSON Web Token (JWT) vulnerability scanner module
"""

import re
import logging
import random
import requests
import base64
import json
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style

logger = logging.getLogger('CyberWolf.JWTScanner')

class JWTScanner:
    """
    Scanner module for detecting JSON Web Token vulnerabilities
    """
    
    def __init__(self, timeout=10, verbose=False):
        """
        Initialize the JWT scanner
        
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
        
        # Common JWT locations
        self.jwt_locations = [
            'Authorization',
            'x-access-token',
            'jwt',
            'token',
            'id_token',
            'access_token'
        ]
        
        # Common weak JWT signing algorithms
        self.weak_algorithms = [
            'none',
            'HS256',  # Not weak by itself, but often implemented poorly
            'RS256'   # Not weak by itself, but often implemented poorly
        ]
        
        self.session = requests.Session()
    
    def scan(self, url, api_key=None):
        """
        Scan the given URL for JWT vulnerabilities
        
        Args:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
        
        Returns:
            list: Found JWT vulnerabilities details
        """
        logger.info(f"Starting JWT scan on {url}")
        vulnerabilities = []
        
        try:
            # Get random user agent
            headers = {'User-Agent': random.choice(self.user_agents)}
            
            # First, get the page to check for JWT tokens
            response = self.session.get(
                url, 
                headers=headers, 
                timeout=self.timeout,
                verify=True
            )
            response.raise_for_status()
            
            # Check response headers for JWT tokens
            jwt_tokens = self._extract_jwt_from_headers(response.headers)
            
            # Check response body for JWT tokens
            body_tokens = self._extract_jwt_from_body(response.text)
            jwt_tokens.extend(body_tokens)
            
            # Check cookies for JWT tokens
            cookie_tokens = self._extract_jwt_from_cookies(response.cookies)
            jwt_tokens.extend(cookie_tokens)
            
            # Analyze found tokens
            if jwt_tokens:
                self._log_verbose(f"Found {len(jwt_tokens)} JWT tokens to analyze")
                for token_info in jwt_tokens:
                    token_vulns = self._analyze_jwt_token(token_info)
                    vulnerabilities.extend(token_vulns)
            
            # Use API for enhanced scanning if available
            if api_key:
                self._log_verbose("Using API for enhanced JWT scanning")
                api_vulns = self._api_enhanced_scan(url, api_key)
                vulnerabilities.extend(api_vulns)
            
            logger.info(f"JWT scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except requests.RequestException as e:
            logger.error(f"Request error during JWT scan: {str(e)}")
            print(f"{Fore.RED}[!] Error during JWT scan: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _extract_jwt_from_headers(self, headers):
        """
        Extract JWT tokens from response headers
        
        Args:
            headers (dict): Response headers
        
        Returns:
            list: Found JWT tokens with location info
        """
        tokens = []
        
        for header_name, header_value in headers.items():
            if header_name.lower() in [loc.lower() for loc in self.jwt_locations]:
                # Check if it's a Bearer token
                if header_value.startswith('Bearer '):
                    token = header_value[7:]  # Remove 'Bearer ' prefix
                else:
                    token = header_value
                
                if self._is_jwt_token(token):
                    tokens.append({
                        'token': token,
                        'location': f'Header: {header_name}',
                        'source': 'response_header'
                    })
        
        return tokens
    
    def _extract_jwt_from_body(self, body):
        """
        Extract JWT tokens from response body
        
        Args:
            body (str): Response body
        
        Returns:
            list: Found JWT tokens with location info
        """
        tokens = []
        
        # JWT pattern: base64url.base64url.base64url
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        matches = re.findall(jwt_pattern, body)
        
        for match in matches:
            if self._is_jwt_token(match):
                tokens.append({
                    'token': match,
                    'location': 'Response Body',
                    'source': 'response_body'
                })
        
        return tokens
    
    def _extract_jwt_from_cookies(self, cookies):
        """
        Extract JWT tokens from cookies
        
        Args:
            cookies (CookieJar): Response cookies
        
        Returns:
            list: Found JWT tokens with location info
        """
        tokens = []
        
        for cookie in cookies:
            if cookie.name.lower() in [loc.lower() for loc in self.jwt_locations]:
                if self._is_jwt_token(cookie.value):
                    tokens.append({
                        'token': cookie.value,
                        'location': f'Cookie: {cookie.name}',
                        'source': 'cookie'
                    })
        
        return tokens
    
    def _is_jwt_token(self, token):
        """
        Check if a string is a valid JWT token
        
        Args:
            token (str): Token to check
        
        Returns:
            bool: True if token is a valid JWT, False otherwise
        """
        # JWT format: header.payload.signature
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        # Try to decode the header
        try:
            # Add padding if needed
            header = parts[0]
            padding = '=' * (4 - len(header) % 4)
            header_decoded = base64.urlsafe_b64decode(header + padding)
            header_json = json.loads(header_decoded)
            
            # Check if it has typical JWT header fields
            if 'alg' in header_json:
                return True
        except:
            pass
        
        return False
    
    def _analyze_jwt_token(self, token_info):
        """
        Analyze JWT token for vulnerabilities
        
        Args:
            token_info (dict): Token information
        
        Returns:
            list: Vulnerabilities found
        """
        vulnerabilities = []
        token = token_info['token']
        
        try:
            # Split the token
            parts = token.split('.')
            
            # Decode the header
            header = parts[0]
            padding = '=' * (4 - len(header) % 4)
            header_decoded = base64.urlsafe_b64decode(header + padding)
            header_json = json.loads(header_decoded)
            
            # Check for 'none' algorithm
            if header_json.get('alg', '').lower() == 'none':
                self._log_verbose(f"Found JWT using 'none' algorithm")
                vulnerabilities.append({
                    'type': 'JWT',
                    'subtype': 'None Algorithm',
                    'location': token_info['location'],
                    'token': token[:10] + '...',  # Truncate for security
                    'severity': 'High',
                    'confidence': 'High',
                    'description': "JWT uses 'none' algorithm which allows signature bypass"
                })
            
            # Check for weak algorithms
            alg = header_json.get('alg', '')
            if alg in self.weak_algorithms:
                self._log_verbose(f"Found JWT using potentially weak algorithm: {alg}")
                vulnerabilities.append({
                    'type': 'JWT',
                    'subtype': 'Weak Algorithm',
                    'location': token_info['location'],
                    'token': token[:10] + '...',  # Truncate for security
                    'algorithm': alg,
                    'severity': 'Medium',
                    'confidence': 'Medium',
                    'description': f"JWT uses potentially weak algorithm: {alg}"
                })
            
            # Check for missing 'typ' claim
            if 'typ' not in header_json:
                self._log_verbose(f"Found JWT missing 'typ' claim")
                vulnerabilities.append({
                    'type': 'JWT',
                    'subtype': 'Missing Type',
                    'location': token_info['location'],
                    'token': token[:10] + '...',  # Truncate for security
                    'severity': 'Low',
                    'confidence': 'Medium',
                    'description': "JWT is missing 'typ' claim in header"
                })
            
        except Exception as e:
            logger.error(f"Error analyzing JWT token: {str(e)}")
        
        return vulnerabilities
    
    def _api_enhanced_scan(self, url, api_key):
        """
        Use API for enhanced JWT scanning (placeholder for actual API integration)
        
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
            print(f"{Fore.CYAN}[JWT] {message}{Style.RESET_ALL}")
