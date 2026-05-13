"""
Path and directory vulnerability scanner module
"""

import logging
import random
import requests
from urllib.parse import urljoin
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger('CyberWolf.PathScanner')

class PathScanner:
    """
    Scanner module for detecting vulnerable paths, directories, and files
    """
    
    def __init__(self, timeout=10, verbose=False):
        """
        Initialize the path scanner
        
        Args:
            timeout (int): Request timeout in seconds
            verbose (bool): Enable verbose output
        """
        self.timeout = timeout
        self.verbose = verbose
        
        # Common vulnerable paths to check
        self.vulnerable_paths = [
            # Config files
            ".env",
            ".git/config",
            "config.php",
            "wp-config.php",
            "config.json",
            "config.xml",
            
            # Admin panels
            "admin/",
            "administrator/",
            "wp-admin/",
            "admin.php",
            "admin.html",
            "dashboard/",
            "cp/",
            "phpmyadmin/",
            
            # Default files
            "phpinfo.php",
            "info.php",
            "test.php",
            "default.php",
            "index.php.bak",
            "index.php~",
            
            # API endpoints
            "api/",
            "api/v1/",
            "api/users",
            "api/admin",
            
            # Upload directories
            "uploads/",
            "upload/",
            "files/",
            "images/",
            
            # Backup files
            "backup/",
            "backup.sql",
            "dump.sql",
            "backup.zip",
            
            # Log files
            "logs/",
            "error_log",
            "error.log",
            "access.log",
            
            # Server files
            ".htaccess",
            "server-status",
            "web.config",
            
            # Potentially dangerous files
            "shell.php",
            "c99.php",
            "r57.php",
            "webshell.php",
            
            # Development/debugging
            "debug.php",
            "debug/",
            "dev/",
            "development/",
            "test/",
            "testing/",
            
            # Potentially vulnerable scripts
            "cgi-bin/",
            "install/",
            "setup/",
            "install.php",
            "setup.php"
        ]
        
        # User agents to mimic browser
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
        ]
        
        self.session = requests.Session()
    
    def scan(self, url, api_key=None):
        """
        Scan the given URL for vulnerable paths and directories
        
        Args:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
        
        Returns:
            list: Found vulnerable paths
        """
        logger.info(f"Starting path scan on {url}")
        
        # Ensure URL ends with a slash if it's the domain root
        if url.endswith('/'):
            base_url = url
        else:
            base_url = url + '/'
        
        # Normalize the URL to ensure it's a valid base
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'http://' + base_url
        
        vulnerabilities = []
        
        self._log_verbose(f"Scanning {len(self.vulnerable_paths)} potential paths")
        
        # Use ThreadPoolExecutor to speed up scanning
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_path = {
                executor.submit(self._check_path, base_url, path): path 
                for path in self.vulnerable_paths
            }
            
            for future in future_to_path:
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
                except Exception as e:
                    logger.error(f"Error checking path {path}: {str(e)}")
        
        # Use API for enhanced scanning if available
        if api_key:
            self._log_verbose("Using API for enhanced path scanning")
            api_vulns = self._api_enhanced_scan(base_url, api_key)
            vulnerabilities.extend(api_vulns)
        
        logger.info(f"Path scan completed. Found {len(vulnerabilities)} vulnerable paths")
        return vulnerabilities
    
    def _check_path(self, base_url, path):
        """
        Check if a path exists and is accessible
        
        Args:
            base_url (str): Base URL
            path (str): Path to check
        
        Returns:
            dict: Vulnerability information if found, None otherwise
        """
        url = urljoin(base_url, path)
        
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=False)
            
            # Check if the path exists based on status code
            if response.status_code in [200, 403]:  # 200 OK or 403 Forbidden (meaning it exists but access denied)
                status = "Found"
                risk = "Medium"
                
                # Check content to determine if it's a sensitive file
                sensitive_terms = ["password", "config", "secret", "private", "admin", "root", "token", "api"]
                content_type = response.headers.get('Content-Type', '')
                
                # Higher risk for certain content types and terms
                if any(term in path.lower() for term in sensitive_terms):
                    risk = "High"
                    
                if "text/plain" in content_type or "application/json" in content_type:
                    if response.status_code == 200 and len(response.text) > 0:
                        status = "Accessible"
                        risk = "High"
                
                self._log_verbose(f"Found vulnerable path: {path} (Status: {response.status_code})")
                
                return {
                    'type': 'Vulnerable Path',
                    'path': path,
                    'full_url': url,
                    'status_code': response.status_code,
                    'content_type': content_type,
                    'risk_level': risk,
                    'status': status
                }
                
        except requests.RequestException:
            # Skip failures
            pass
        
        return None
    
    def _api_enhanced_scan(self, url, api_key):
        """
        Use API for enhanced path scanning
        
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
            print(f"{Fore.CYAN}[Path] {message}{Style.RESET_ALL}")
