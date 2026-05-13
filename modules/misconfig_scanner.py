"""
Security misconfiguration vulnerability scanner module
"""
import logging
import re
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from requests.exceptions import RequestException, Timeout
from colorama import Fore, Style

logger = logging.getLogger('CyberWolf.MisconfigScanner')

class MisconfigScanner:
    """
    Scanner module for detecting security misconfigurations
    """
    def __init__(self, timeout=10, verbose=False):
        """
        Initialize the security misconfiguration scanner
        
        Args:
            timeout (int): Request timeout in seconds
            verbose (bool): Enable verbose output
        """
        self.timeout = timeout
        self.verbose = verbose
        self.headers = {
            'User-Agent': 'CyberWolf-Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        
    def scan(self, url, api_key=None):
        """
        Scan the given URL for security misconfigurations
        
        Args:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
        
        Returns:
            list: Found security misconfiguration vulnerabilities
        """
        self._log_verbose(f"Starting security misconfiguration scan on {url}")
        misconfigs = []
        
        try:
            # Basic security header checks
            header_vulns = self._check_security_headers(url)
            misconfigs.extend(header_vulns)
            
            # Check for exposed server information
            server_info_vulns = self._check_server_info(url)
            misconfigs.extend(server_info_vulns)
            
            # Check for default files and directories
            default_resource_vulns = self._check_default_resources(url)
            misconfigs.extend(default_resource_vulns)
            
            # Check for exposed environment information
            env_info_vulns = self._check_environment_info(url)
            misconfigs.extend(env_info_vulns)
            
            # Enhanced scanning with API if key is provided
            if api_key:
                self._log_verbose("Using API-enhanced scanning for misconfigurations")
                api_vulns = self._api_enhanced_scan(url, api_key)
                misconfigs.extend(api_vulns)
            
            # Log scan completion
            logger.info(f"Security misconfiguration scan completed. Found {len(misconfigs)} issues")
            if misconfigs:
                print(f"{Fore.YELLOW}[+] Found {len(misconfigs)} security misconfiguration issues{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] No security misconfiguration issues found{Style.RESET_ALL}")
                
            return misconfigs
            
        except Exception as e:
            logger.error(f"Error during security misconfiguration scan: {str(e)}")
            print(f"{Fore.RED}[!] Error during security misconfiguration scan: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _check_security_headers(self, url):
        """
        Check for missing or misconfigured security headers
        
        Args:
            url (str): Target URL
        
        Returns:
            list: Header-related vulnerabilities found
        """
        self._log_verbose("Checking security headers")
        vulns = []
        
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=True)
            headers = response.headers
            
            # Define important security headers to check
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header - increases risk of MITM attacks',
                'Content-Security-Policy': 'Missing Content-Security-Policy header - increases risk of XSS',
                'X-Frame-Options': 'Missing X-Frame-Options header - increases risk of clickjacking',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header - increases risk of MIME-sniffing attacks',
                'Referrer-Policy': 'Missing Referrer-Policy header - may leak sensitive information in referrer',
                'Permissions-Policy': 'Missing Permissions-Policy header - lacks control over browser features'
            }
            
            for header, risk in security_headers.items():
                if header not in headers:
                    vuln = {
                        'type': 'missing_security_header',
                        'header': header,
                        'description': risk,
                        'severity': 'Medium',
                        'evidence': f"Response headers do not include {header}",
                        'mitigation': f"Add the {header} header to HTTP responses"
                    }
                    vulns.append(vuln)
                    self._log_verbose(f"Found missing security header: {header}")
            
            # Check for insecure cookie flags
            if 'Set-Cookie' in headers:
                # Get the cookie value(s)
                cookie_value = headers.get('Set-Cookie', '')
                if cookie_value:
                    # Check for HttpOnly flag
                    if 'HttpOnly' not in cookie_value:
                        vuln = {
                            'type': 'insecure_cookie',
                            'header': 'Set-Cookie',
                            'description': 'Cookie missing HttpOnly flag - vulnerable to XSS cookie theft',
                            'severity': 'Medium',
                            'evidence': cookie_value,
                            'mitigation': "Add HttpOnly flag to cookies containing sensitive data"
                        }
                        vulns.append(vuln)
                        self._log_verbose("Found cookie missing HttpOnly flag")
                    
                    # Check for Secure flag if HTTPS
                    if 'Secure' not in cookie_value and url.startswith('https'):
                        vuln = {
                            'type': 'insecure_cookie',
                            'header': 'Set-Cookie',
                            'description': 'Cookie missing Secure flag - vulnerable to MITM attacks',
                            'severity': 'Medium',
                            'evidence': cookie_value,
                            'mitigation': "Add Secure flag to cookies used over HTTPS"
                        }
                        vulns.append(vuln)
                        self._log_verbose("Found cookie missing Secure flag")
            
            return vulns
            
        except RequestException as e:
            logger.error(f"Error checking security headers: {str(e)}")
            return []
    
    def _check_server_info(self, url):
        """
        Check for exposed server information that could be leveraged for attacks
        
        Args:
            url (str): Target URL
        
        Returns:
            list: Server information disclosure vulnerabilities
        """
        self._log_verbose("Checking for exposed server information")
        vulns = []
        
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            headers = response.headers
            
            # Check Server header
            if 'Server' in headers:
                server = headers['Server']
                if len(server) > 0 and not server.lower() in ['apache', 'nginx', 'iis']:
                    # Detailed server info found
                    vuln = {
                        'type': 'info_disclosure',
                        'header': 'Server',
                        'description': 'Detailed server information disclosure',
                        'severity': 'Low',
                        'evidence': server,
                        'mitigation': "Configure server to limit information in Server header"
                    }
                    vulns.append(vuln)
                    self._log_verbose(f"Found detailed server information: {server}")
            
            # Check X-Powered-By header
            if 'X-Powered-By' in headers:
                powered_by = headers['X-Powered-By']
                vuln = {
                    'type': 'info_disclosure',
                    'header': 'X-Powered-By',
                    'description': 'Technology stack information disclosure',
                    'severity': 'Low',
                    'evidence': powered_by,
                    'mitigation': "Remove X-Powered-By header from responses"
                }
                vulns.append(vuln)
                self._log_verbose(f"Found X-Powered-By information: {powered_by}")
            
            return vulns
            
        except RequestException as e:
            logger.error(f"Error checking server information: {str(e)}")
            return []
    
    def _check_default_resources(self, url):
        """
        Check for default resources, files, and configurations
        
        Args:
            url (str): Target URL
        
        Returns:
            list: Default resource vulnerabilities found
        """
        self._log_verbose("Checking for default resources and configurations")
        vulns = []
        
        # Common default files and directories to check
        default_resources = [
            '/admin', '/administrator', '/login', '/wp-admin', '/phpmyadmin', '/config',
            '/app/config', '/app/etc/local.xml', '/config.php', '/configuration.php',
            '/DEBUG', '/debug', '/test', '/test.php', '/phpinfo.php', '/info.php',
            '/server-status', '/server-info', '/.git', '/.gitignore', '/.env', '/.htaccess',
            '/console', '/web.config', '/elmah.axd', '/trace.axd', '/robots.txt'
        ]
        
        for resource in default_resources:
            try:
                resource_url = urljoin(url, resource)
                response = requests.get(resource_url, headers=self.headers, timeout=self.timeout, allow_redirects=False)
                
                # Check if resource exists (by status code)
                if response.status_code == 200:
                    vuln = {
                        'type': 'default_resource',
                        'url': resource_url,
                        'description': f'Default or sensitive resource found: {resource}',
                        'severity': 'Medium',
                        'evidence': f"Status code: {response.status_code}, Content length: {len(response.content)}",
                        'mitigation': f"Remove or restrict access to {resource}"
                    }
                    vulns.append(vuln)
                    self._log_verbose(f"Found default resource: {resource}")
                
                # For sensitive files, check if content suggests it's the actual file we're looking for
                if resource in ['/phpinfo.php', '/info.php'] and response.status_code == 200:
                    if 'PHP Version' in response.text and 'PHP License' in response.text:
                        vuln = {
                            'type': 'sensitive_info',
                            'url': resource_url,
                            'description': 'PHP information disclosure page found',
                            'severity': 'High',
                            'evidence': "PHP information page detected",
                            'mitigation': "Remove phpinfo files from production environment"
                        }
                        vulns.append(vuln)
                        self._log_verbose(f"Found PHP info page at: {resource}")
                
            except RequestException:
                # Skip resources that can't be accessed
                continue
        
        return vulns
    
    def _check_environment_info(self, url):
        """
        Check for exposed environment information (debug modes, error details, etc.)
        
        Args:
            url (str): Target URL
        
        Returns:
            list: Environment information vulnerabilities found
        """
        self._log_verbose("Checking for exposed environment information")
        vulns = []
        
        try:
            # Try to trigger error by requesting a non-existent page with unusual extension
            error_url = urljoin(url, '/cyberwolf_non_existent_page_test.' + str(hash(url))[:6])
            response = requests.get(error_url, headers=self.headers, timeout=self.timeout)
            
            # Check for detailed error messages
            error_indicators = [
                'stack trace', 'exception', 'traceback', 'syntax error', 
                'runtime error', 'error on line', 'fatal error',
                'warning:', 'notice:', 'deprecated:', 'debug trace', 
                'SQL syntax', 'database error', 'ORA-', 'MySQL', 
                'ODBC', 'JDBC', 'PostgreSQL', 'SQLite'
            ]
            
            for indicator in error_indicators:
                if indicator.lower() in response.text.lower():
                    vuln = {
                        'type': 'verbose_errors',
                        'url': error_url,
                        'description': 'Detailed error messages exposed to users',
                        'severity': 'Medium',
                        'evidence': f"Error message contains: {indicator}",
                        'mitigation': "Configure application to display generic error messages in production"
                    }
                    vulns.append(vuln)
                    self._log_verbose(f"Found detailed error information: {indicator}")
                    break  # One finding is enough for this type
            
            # Check for development/debug mode indicators in the page
            debug_indicators = [
                'debug mode', 'development mode', 'dev mode', 'testing environment',
                'debug info', 'debug toolbar', 'django debug', 'laravel debugbar',
                'symfony debug', 'debug panel'
            ]
            
            # Check homepage for debug indicators
            home_response = requests.get(url, headers=self.headers, timeout=self.timeout)
            for indicator in debug_indicators:
                if indicator.lower() in home_response.text.lower():
                    vuln = {
                        'type': 'debug_mode',
                        'url': url,
                        'description': 'Application running in debug/development mode',
                        'severity': 'High',
                        'evidence': f"Page contains: {indicator}",
                        'mitigation': "Disable debug mode in production environment"
                    }
                    vulns.append(vuln)
                    self._log_verbose(f"Found debug mode indicator: {indicator}")
                    break  # One finding is enough for this type
            
            return vulns
            
        except RequestException as e:
            logger.error(f"Error checking environment information: {str(e)}")
            return []
    
    def _api_enhanced_scan(self, url, api_key):
        """
        Use API for enhanced security misconfiguration scanning
        
        Args:
            url (str): Target URL
            api_key (str): API key for authentication
        
        Returns:
            list: Additional vulnerabilities found via API
        """
        # This is a placeholder for actual API integration
        # In a real implementation, this would call an external API service
        self._log_verbose(f"Using API-enhanced scanning for {url}")
        
        # Placeholder for API-discovered vulnerabilities
        # In a real implementation, these would come from the API
        return []
    
    def _log_verbose(self, message):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            print(f"{Fore.BLUE}[Debug] {message}{Style.RESET_ALL}")
            logger.debug(message)