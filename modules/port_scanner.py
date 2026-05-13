"""
Port scanning and service detection module
"""

import logging
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

logger = logging.getLogger('CyberWolf.PortScanner')

class PortScanner:
    """
    Scanner module for detecting open ports and services
    """
    
    def __init__(self, timeout=10, verbose=False):
        """
        Initialize the port scanner
        
        Args:
            timeout (int): Scan timeout in seconds
            verbose (bool): Enable verbose output
        """
        self.timeout = timeout
        self.verbose = verbose
        
        # Common ports to scan if nmap is not available
        self.common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            111,   # RPC
            135,   # MS-RPC
            139,   # NetBIOS
            143,   # IMAP
            443,   # HTTPS
            445,   # SMB
            993,   # IMAPS
            995,   # POP3S
            1723,  # PPTP
            3306,  # MySQL
            3389,  # RDP
            5900,  # VNC
            8080   # HTTP Proxy
        ]
        
        # Common service names by port
        self.service_names = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "MS-RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP Proxy"
        }
    
    def scan(self, url, api_key=None):
        """
        Scan the given URL for open ports and services
        
        Args:
            url (str): Target URL to scan
            api_key (str, optional): API key for enhanced scanning
        
        Returns:
            list: Found open ports and services
        """
        # Extract hostname from URL
        parsed_url = urllib.parse.urlparse(url)
        host = parsed_url.netloc
        
        # Remove port from hostname if present
        if ':' in host:
            host = host.split(':')[0]
        
        logger.info(f"Starting port scan on {host}")
        self._log_verbose(f"Resolving IP address for {host}")
        
        try:
            ip_address = socket.gethostbyname(host)
            self._log_verbose(f"Resolved {host} to {ip_address}")
        except socket.gaierror:
            logger.error(f"Could not resolve hostname: {host}")
            print(f"{Fore.RED}[!] Could not resolve hostname: {host}{Style.RESET_ALL}")
            return []
        
        # Choose scanning method based on availability
        if NMAP_AVAILABLE:
            return self._nmap_scan(ip_address, host)
        else:
            return self._basic_scan(ip_address, host)
    
    def _nmap_scan(self, ip_address, hostname):
        """
        Perform port scan using nmap
        
        Args:
            ip_address (str): Target IP address
            hostname (str): Original hostname
        
        Returns:
            list: Open ports and services
        """
        self._log_verbose("Using nmap for port scanning")
        
        try:
            nm = nmap.PortScanner()
            # Perform a basic TCP SYN scan of common ports
            nm.scan(ip_address, '21-25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080', arguments='-sS -T4')
            
            results = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = sorted(nm[host][proto].keys())
                    for port in lport:
                        if nm[host][proto][port]['state'] == 'open':
                            service = nm[host][proto][port]['name']
                            product = nm[host][proto][port].get('product', '')
                            version = nm[host][proto][port].get('version', '')
                            
                            service_info = service
                            if product:
                                service_info += f" ({product}"
                                if version:
                                    service_info += f" {version}"
                                service_info += ")"
                            
                            results.append({
                                'port': port,
                                'protocol': proto,
                                'service': service_info,
                                'state': 'open'
                            })
                            
                            self._log_verbose(f"Found open port {port}/{proto}: {service_info}")
            
            return results
            
        except Exception as e:
            logger.error(f"Error during nmap scan: {str(e)}")
            print(f"{Fore.RED}[!] Error during nmap scan: {str(e)}{Style.RESET_ALL}")
            # Fall back to basic scan
            return self._basic_scan(ip_address, hostname)
    
    def _basic_scan(self, ip_address, hostname):
        """
        Perform basic port scan using sockets
        
        Args:
            ip_address (str): Target IP address
            hostname (str): Original hostname
        
        Returns:
            list: Open ports and services
        """
        self._log_verbose("Using basic socket scan (nmap not available)")
        
        results = []
        
        # Use ThreadPoolExecutor to speed up scanning
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {
                executor.submit(self._check_port, ip_address, port): port 
                for port in self.common_ports
            }
            
            for future in future_to_port:
                port = future_to_port[future]
                try:
                    is_open = future.result()
                    if is_open:
                        service = self.service_names.get(port, "Unknown")
                        results.append({
                            'port': port,
                            'protocol': 'tcp',
                            'service': service,
                            'state': 'open'
                        })
                        self._log_verbose(f"Found open port {port}/tcp: {service}")
                except Exception as e:
                    logger.error(f"Error checking port {port}: {str(e)}")
        
        return results
    
    def _check_port(self, ip_address, port):
        """
        Check if a port is open
        
        Args:
            ip_address (str): Target IP address
            port (int): Port to check
        
        Returns:
            bool: True if port is open, False otherwise
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout / 5)  # Short timeout for port check
        
        try:
            result = sock.connect_ex((ip_address, port))
            return result == 0  # Port is open if result is 0
        except:
            return False
        finally:
            sock.close()
    
    def _log_verbose(self, message):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            logger.debug(message)
            print(f"{Fore.CYAN}[Port] {message}{Style.RESET_ALL}")
