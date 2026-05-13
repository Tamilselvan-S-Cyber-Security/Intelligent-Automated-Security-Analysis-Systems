"""
SSL/TLS security scanner module
"""

import re
import logging
import socket
import ssl
import datetime
from urllib.parse import urlparse
from colorama import Fore, Style

logger = logging.getLogger('CyberWolf.SSLScanner')

class SSLScanner:
    """
    Scanner module for detecting SSL/TLS vulnerabilities and misconfigurations
    """
    
    def __init__(self, timeout=10, verbose=False):
        """
        Initialize the SSL/TLS scanner
        
        Args:
            timeout (int): Connection timeout in seconds
            verbose (bool): Enable verbose output
        """
        self.timeout = timeout
        self.verbose = verbose
        
        # Weak SSL/TLS protocols
        self.weak_protocols = [
            ssl.PROTOCOL_SSLv2,  # Deprecated in Python 3.6
            ssl.PROTOCOL_SSLv3,  # Deprecated in Python 3.6
            ssl.PROTOCOL_TLSv1,
            ssl.PROTOCOL_TLSv1_1
        ]
        
        # Weak cipher suites
        self.weak_ciphers = [
            'NULL', 
            'EXPORT', 
            'RC4', 
            'DES', 
            '3DES', 
            'MD5', 
            'SHA1', 
            'ANON',
            'ADH',
            'AECDH',
            'EXP',
            'EXP1024',
            'IDEA',
            'aNULL',
            'eNULL'
        ]
        
        # Secure protocols
        self.secure_protocols = [
            ssl.PROTOCOL_TLSv1_2,
            ssl.PROTOCOL_TLSv1_3
        ]
    
    def scan(self, url, api_key=None):
        """
        Scan the given URL for SSL/TLS vulnerabilities
        
        Args:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
        
        Returns:
            list: Found SSL/TLS vulnerabilities details
        """
        logger.info(f"Starting SSL/TLS scan on {url}")
        vulnerabilities = []
        
        try:
            # Parse URL to get hostname and port safely
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port

            if not hostname:
                self._log_verbose(f"Unable to parse hostname from URL: {url}")
                return vulnerabilities

            # Default ports based on scheme
            if port is None:
                port = 443 if parsed_url.scheme == 'https' else 80
            
            # Skip non-HTTPS URLs
            if parsed_url.scheme != 'https':
                self._log_verbose(f"Skipping SSL/TLS scan for non-HTTPS URL: {url}")
                return vulnerabilities
            
            self._log_verbose(f"Checking SSL/TLS configuration for {hostname}:{port}")
            
            # Check certificate
            cert_vulns = self._check_certificate(hostname, port)
            vulnerabilities.extend(cert_vulns)
            
            # Check supported protocols
            protocol_vulns = self._check_protocols(hostname, port)
            vulnerabilities.extend(protocol_vulns)
            
            # Check cipher suites
            cipher_vulns = self._check_cipher_suites(hostname, port)
            vulnerabilities.extend(cipher_vulns)
            
            # Check for Heartbleed vulnerability
            heartbleed_vulns = self._check_heartbleed(hostname, port)
            vulnerabilities.extend(heartbleed_vulns)
            
            # Use API for enhanced scanning if available
            if api_key:
                self._log_verbose("Using API for enhanced SSL/TLS scanning")
                api_vulns = self._api_enhanced_scan(url, api_key)
                vulnerabilities.extend(api_vulns)
            
            logger.info(f"SSL/TLS scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error during SSL/TLS scan: {str(e)}")
            print(f"{Fore.RED}[!] Error during SSL/TLS scan: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _check_certificate(self, hostname, port):
        """
        Check SSL certificate for vulnerabilities
        
        Args:
            hostname (str): Target hostname
            port (int): Target port
        
        Returns:
            list: Certificate vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect to the server
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert(binary_form=False)
                    
                    # Check certificate expiration
                    if 'notAfter' in cert:
                        expires = ssl.cert_time_to_seconds(cert['notAfter'])
                        remaining = expires - datetime.datetime.now().timestamp()
                        days_remaining = remaining / (24 * 3600)
                        
                        if days_remaining < 0:
                            self._log_verbose(f"Certificate for {hostname} has expired")
                            vulnerabilities.append({
                                'type': 'SSL/TLS',
                                'subtype': 'Expired Certificate',
                                'hostname': hostname,
                                'port': port,
                                'severity': 'High',
                                'confidence': 'High',
                                'description': f'SSL certificate has expired on {cert["notAfter"]}'
                            })
                        elif days_remaining < 30:
                            self._log_verbose(f"Certificate for {hostname} expires soon ({days_remaining:.1f} days)")
                            vulnerabilities.append({
                                'type': 'SSL/TLS',
                                'subtype': 'Certificate Expiring Soon',
                                'hostname': hostname,
                                'port': port,
                                'severity': 'Medium',
                                'confidence': 'High',
                                'description': f'SSL certificate expires in {days_remaining:.1f} days'
                            })
                    
                    # Check for self-signed certificate
                    if 'issuer' in cert and 'subject' in cert:
                        if cert['issuer'] == cert['subject']:
                            self._log_verbose(f"Self-signed certificate detected for {hostname}")
                            vulnerabilities.append({
                                'type': 'SSL/TLS',
                                'subtype': 'Self-Signed Certificate',
                                'hostname': hostname,
                                'port': port,
                                'severity': 'Medium',
                                'confidence': 'High',
                                'description': 'Server is using a self-signed certificate'
                            })
                    
                    # Check for weak signature algorithm
                    if 'SIGNATURE_ALGORITHM' in dir(ssock) and hasattr(ssock, 'SIGNATURE_ALGORITHM'):
                        sig_alg = ssock.SIGNATURE_ALGORITHM
                        if 'md5' in sig_alg.lower() or 'sha1' in sig_alg.lower():
                            self._log_verbose(f"Weak signature algorithm detected: {sig_alg}")
                            vulnerabilities.append({
                                'type': 'SSL/TLS',
                                'subtype': 'Weak Signature Algorithm',
                                'hostname': hostname,
                                'port': port,
                                'algorithm': sig_alg,
                                'severity': 'Medium',
                                'confidence': 'High',
                                'description': f'Certificate uses weak signature algorithm: {sig_alg}'
                            })
        
        except Exception as e:
            logger.error(f"Error checking certificate: {str(e)}")
        
        return vulnerabilities
    
    def _check_protocols(self, hostname, port):
        """
        Check supported SSL/TLS protocols
        
        Args:
            hostname (str): Target hostname
            port (int): Target port
        
        Returns:
            list: Protocol vulnerabilities found
        """
        vulnerabilities = []
        
        # Check for weak protocols
        for protocol in self.weak_protocols:
            try:
                # Create context with specific protocol
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Try to connect
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # If we get here, the protocol is supported
                        protocol_name = self._get_protocol_name(protocol)
                        self._log_verbose(f"Server supports weak protocol: {protocol_name}")
                        vulnerabilities.append({
                            'type': 'SSL/TLS',
                            'subtype': 'Weak Protocol',
                            'hostname': hostname,
                            'port': port,
                            'protocol': protocol_name,
                            'severity': 'High',
                            'confidence': 'High',
                            'description': f'Server supports weak protocol: {protocol_name}'
                        })
            except:
                # Protocol not supported (good)
                pass
        
        # Check if secure protocols are supported
        secure_supported = False
        for protocol in self.secure_protocols:
            try:
                # Create context with specific protocol
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Try to connect
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # If we get here, the protocol is supported
                        secure_supported = True
                        break
            except:
                # Protocol not supported
                pass
        
        if not secure_supported:
            self._log_verbose(f"Server does not support secure protocols")
            vulnerabilities.append({
                'type': 'SSL/TLS',
                'subtype': 'No Secure Protocols',
                'hostname': hostname,
                'port': port,
                'severity': 'Critical',
                'confidence': 'High',
                'description': 'Server does not support secure protocols (TLS 1.2 or TLS 1.3)'
            })
        
        return vulnerabilities
    
    def _check_cipher_suites(self, hostname, port):
        """
        Check supported cipher suites
        
        Args:
            hostname (str): Target hostname
            port (int): Target port
        
        Returns:
            list: Cipher vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Create default context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect to the server
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get current cipher
                    current_cipher = ssock.cipher()
                    if current_cipher:
                        cipher_name = current_cipher[0]
                        
                        # Check if it's a weak cipher
                        if any(weak in cipher_name.upper() for weak in self.weak_ciphers):
                            self._log_verbose(f"Server uses weak cipher: {cipher_name}")
                            vulnerabilities.append({
                                'type': 'SSL/TLS',
                                'subtype': 'Weak Cipher',
                                'hostname': hostname,
                                'port': port,
                                'cipher': cipher_name,
                                'severity': 'High',
                                'confidence': 'High',
                                'description': f'Server uses weak cipher: {cipher_name}'
                            })
        
        except Exception as e:
            logger.error(f"Error checking cipher suites: {str(e)}")
        
        return vulnerabilities
    
    def _check_heartbleed(self, hostname, port):
        """
        Check for Heartbleed vulnerability (CVE-2014-0160)
        
        Args:
            hostname (str): Target hostname
            port (int): Target port
        
        Returns:
            list: Heartbleed vulnerabilities found
        """
        vulnerabilities = []
        
        # This is a simplified check - in a real scanner, you would need a proper Heartbleed test
        try:
            # Create context with TLS 1.1 (vulnerable to Heartbleed)
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Try to connect
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                try:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # Check OpenSSL version in cipher description if available
                        if hasattr(ssock, 'version'):
                            version = ssock.version()
                            # OpenSSL 1.0.1 through 1.0.1f are vulnerable
                            if 'OpenSSL 1.0.1' in version and not any(x in version for x in ['g', 'h', 'i', 'j', 'k', 'l']):
                                self._log_verbose(f"Server may be vulnerable to Heartbleed: {version}")
                                vulnerabilities.append({
                                    'type': 'SSL/TLS',
                                    'subtype': 'Heartbleed',
                                    'hostname': hostname,
                                    'port': port,
                                    'version': version,
                                    'severity': 'Critical',
                                    'confidence': 'Medium',
                                    'description': 'Server may be vulnerable to Heartbleed (CVE-2014-0160)'
                                })
                except:
                    pass
        
        except Exception as e:
            logger.error(f"Error checking for Heartbleed: {str(e)}")
        
        return vulnerabilities
    
    def _get_protocol_name(self, protocol):
        """
        Get protocol name from protocol constant
        
        Args:
            protocol: SSL/TLS protocol constant
        
        Returns:
            str: Protocol name
        """
        if protocol == ssl.PROTOCOL_SSLv2:
            return "SSLv2"
        elif protocol == ssl.PROTOCOL_SSLv3:
            return "SSLv3"
        elif protocol == ssl.PROTOCOL_TLSv1:
            return "TLSv1.0"
        elif protocol == ssl.PROTOCOL_TLSv1_1:
            return "TLSv1.1"
        elif protocol == ssl.PROTOCOL_TLSv1_2:
            return "TLSv1.2"
        elif protocol == ssl.PROTOCOL_TLSv1_3:
            return "TLSv1.3"
        else:
            return "Unknown"
    
    def _api_enhanced_scan(self, url, api_key):
        """
        Use API for enhanced SSL/TLS scanning (placeholder for actual API integration)
        
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
            print(f"{Fore.CYAN}[SSL/TLS] {message}{Style.RESET_ALL}")
