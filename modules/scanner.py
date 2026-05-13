"""
Main vulnerability scanner module that coordinates different scanning operations
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style

from modules.xss_scanner import XSSScanner
from modules.sqli_scanner import SQLiScanner
from modules.port_scanner import PortScanner
from modules.path_scanner import PathScanner
from modules.misconfig_scanner import MisconfigScanner
from modules.xxe_scanner import XXEScanner
from modules.ssrf_scanner import SSRFScanner
from modules.rce_scanner import RCEScanner
from modules.idor_scanner import IDORScanner
from modules.csrf_scanner import CSRFScanner
from modules.jwt_scanner import JWTScanner
from modules.api_scanner import APIScanner
from modules.bruteforce_scanner import BruteForceScanner
from modules.ssl_scanner import SSLScanner
from utils.validator import validate_url

logger = logging.getLogger('CyberWolf.Scanner')

class VulnerabilityScanner:
    """Main scanner class that coordinates the scanning process"""

    def __init__(self, url, timeout=10, api_key=None, verbose=False):
        """
        Initialize the vulnerability scanner.

        Args:
            url (str): Target URL to scan
            timeout (int): Request timeout in seconds
            api_key (str, optional): API key for enhanced scanning
            verbose (bool): Enable verbose output
        """
        if not validate_url(url):
            raise ValueError(f"Invalid URL format: {url}")

        self.url = url
        self.timeout = timeout
        self.api_key = api_key
        self.verbose = verbose
        self.results = {
            'xss': [],
            'sqli': [],
            'ports': [],
            'paths': [],
            'misconfig': [],
            'xxe': [],
            'ssrf': [],
            'rce': [],
            'idor': [],
            'csrf': [],
            'jwt': [],
            'api': [],
            'bruteforce': [],
            'ssl': [],
            'summary': {}
        }

        # Initialize scanner modules
        self.xss_scanner = XSSScanner(timeout=timeout, verbose=verbose)
        self.sqli_scanner = SQLiScanner(timeout=timeout, verbose=verbose)
        self.port_scanner = PortScanner(timeout=timeout, verbose=verbose)
        self.path_scanner = PathScanner(timeout=timeout, verbose=verbose)
        self.misconfig_scanner = MisconfigScanner(timeout=timeout, verbose=verbose)
        self.xxe_scanner = XXEScanner(timeout=timeout, verbose=verbose)
        self.ssrf_scanner = SSRFScanner(timeout=timeout, verbose=verbose)
        self.rce_scanner = RCEScanner(timeout=timeout, verbose=verbose)
        self.idor_scanner = IDORScanner(timeout=timeout, verbose=verbose)
        self.csrf_scanner = CSRFScanner(timeout=timeout, verbose=verbose)
        self.jwt_scanner = JWTScanner(timeout=timeout, verbose=verbose)
        self.api_scanner = APIScanner(timeout=timeout, verbose=verbose)
        self.bruteforce_scanner = BruteForceScanner(timeout=timeout, verbose=verbose)
        self.ssl_scanner = SSLScanner(timeout=timeout, verbose=verbose)

        logger.info(f"Initialized vulnerability scanner for: {url}")

    def run_all_scans(self, options=None):
        """
        Execute selected scanning modules and aggregate results

        Args:
            options (dict, optional): Dictionary of scanning options
                Example: {'xss': True, 'sqli': True, 'ports': False, 'paths': True}

        Returns:
            dict: Scan results from all enabled modules
        """
        # If no options provided, run all scans
        if options is None:
            options = {
                'xss': True,
                'sqli': True,
                'ports': True,
                'paths': True,
                'misconfig': True,
                'xxe': True,
                'ssrf': True,
                'rce': True,
                'idor': True,
                'csrf': True,
                'jwt': True,
                'api': True,
                'bruteforce': True,
                'ssl': True
            }

        self._print_status(f"Running vulnerability scan on {self.url} with options: {options}")

        try:
            # Use threading to run selected scans concurrently
            scan_tasks = {}
            with ThreadPoolExecutor(max_workers=8) as executor:
                # Submit only enabled scanning tasks
                if options.get('xss', True):
                    scan_tasks[executor.submit(self._run_xss_scan)] = 'xss'
                if options.get('sqli', True):
                    scan_tasks[executor.submit(self._run_sqli_scan)] = 'sqli'
                if options.get('ports', True):
                    scan_tasks[executor.submit(self._run_port_scan)] = 'ports'
                if options.get('paths', True):
                    scan_tasks[executor.submit(self._run_path_scan)] = 'paths'
                if options.get('misconfig', True):
                    scan_tasks[executor.submit(self._run_misconfig_scan)] = 'misconfig'
                if options.get('xxe', True):
                    scan_tasks[executor.submit(self._run_xxe_scan)] = 'xxe'
                if options.get('ssrf', True):
                    scan_tasks[executor.submit(self._run_ssrf_scan)] = 'ssrf'
                if options.get('rce', True):
                    scan_tasks[executor.submit(self._run_rce_scan)] = 'rce'
                if options.get('idor', True):
                    scan_tasks[executor.submit(self._run_idor_scan)] = 'idor'
                if options.get('csrf', True):
                    scan_tasks[executor.submit(self._run_csrf_scan)] = 'csrf'
                if options.get('jwt', True):
                    scan_tasks[executor.submit(self._run_jwt_scan)] = 'jwt'
                if options.get('api', True):
                    scan_tasks[executor.submit(self._run_api_scan)] = 'api'
                if options.get('bruteforce', True):
                    scan_tasks[executor.submit(self._run_bruteforce_scan)] = 'bruteforce'
                if options.get('ssl', True):
                    scan_tasks[executor.submit(self._run_ssl_scan)] = 'ssl'

                # Process results as they complete
                for future in as_completed(scan_tasks):
                    scan_type = scan_tasks[future]
                    try:
                        result = future.result(timeout=self.timeout)
                        self.results[scan_type] = result
                        vuln_count = len(result) if isinstance(result, list) else 0
                        self.results['summary'][scan_type] = vuln_count

                        status = f"Found {vuln_count} {scan_type} vulnerabilities"
                        self._print_status(status, is_complete=True)

                    except Exception as e:
                        logger.error(f"Error in {scan_type} scan: {str(e)}")
                        self._print_status(f"Error in {scan_type} scan: {str(e)}", is_error=True)
                        self.results[scan_type] = []
                        self.results['summary'][scan_type] = 0

        except KeyboardInterrupt:
            self._print_status("Scan interrupted by user", is_error=True)
            return self.results
        except Exception as e:
            self._print_status(f"Unexpected error during scan: {str(e)}", is_error=True)
            return self.results

        # Calculate overall risk level
        total_vulns = sum(self.results['summary'].values())
        if total_vulns > 10:
            risk_level = "CRITICAL"
        elif total_vulns > 5:
            risk_level = "HIGH"
        elif total_vulns > 2:
            risk_level = "MEDIUM"
        elif total_vulns > 0:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        self.results['summary']['total_vulnerabilities'] = total_vulns
        self.results['summary']['risk_level'] = risk_level

        return self.results

    def _run_xss_scan(self):
        """Run XSS vulnerability scan"""
        self._print_status("Scanning for XSS vulnerabilities...")
        return self.xss_scanner.scan(self.url, self.api_key)

    def _run_sqli_scan(self):
        """Run SQL Injection vulnerability scan"""
        self._print_status("Scanning for SQL Injection vulnerabilities...")
        return self.sqli_scanner.scan(self.url, self.api_key)

    def _run_port_scan(self):
        """Run port scan"""
        self._print_status("Scanning for open ports and services...")
        return self.port_scanner.scan(self.url, self.api_key)

    def _run_path_scan(self):
        """Run path/directory traversal scan"""
        self._print_status("Scanning for vulnerable paths and directories...")
        return self.path_scanner.scan(self.url, self.api_key)

    def _run_misconfig_scan(self):
        """Run security misconfiguration scan"""
        self._print_status("Scanning for security misconfigurations...")
        return self.misconfig_scanner.scan(self.url, self.api_key)

    def _run_xxe_scan(self):
        """Run XXE vulnerability scan"""
        self._print_status("Scanning for XXE vulnerabilities...")
        return self.xxe_scanner.scan(self.url, self.api_key)

    def _run_ssrf_scan(self):
        """Run SSRF vulnerability scan"""
        self._print_status("Scanning for SSRF vulnerabilities...")
        return self.ssrf_scanner.scan(self.url, self.api_key)

    def _run_rce_scan(self):
        """Run RCE vulnerability scan"""
        self._print_status("Scanning for RCE vulnerabilities...")
        return self.rce_scanner.scan(self.url, self.api_key)

    def _run_idor_scan(self):
        """Run IDOR vulnerability scan"""
        self._print_status("Scanning for IDOR vulnerabilities...")
        return self.idor_scanner.scan(self.url, self.api_key)

    def _run_csrf_scan(self):
        """Run CSRF vulnerability scan"""
        self._print_status("Scanning for CSRF vulnerabilities...")
        return self.csrf_scanner.scan(self.url, self.api_key)

    def _run_jwt_scan(self):
        """Run JWT vulnerability scan"""
        self._print_status("Scanning for JWT vulnerabilities...")
        return self.jwt_scanner.scan(self.url, self.api_key)

    def _run_api_scan(self):
        """Run API security scan"""
        self._print_status("Scanning for API security vulnerabilities...")
        return self.api_scanner.scan(self.url, self.api_key)

    def _run_bruteforce_scan(self):
        """Run brute force vulnerability scan"""
        self._print_status("Scanning for brute force vulnerabilities...")
        return self.bruteforce_scanner.scan(self.url, self.api_key)

    def _run_ssl_scan(self):
        """Run SSL/TLS vulnerability scan"""
        self._print_status("Scanning for SSL/TLS vulnerabilities...")
        return self.ssl_scanner.scan(self.url, self.api_key)

    def _print_status(self, message, is_complete=False, is_error=False):
        """Print status message with appropriate formatting"""
        if is_error:
            print(f"{Fore.RED}[!] {message}{Style.RESET_ALL}")
        elif is_complete:
            print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}")

        if self.verbose:
            logger.info(message)
