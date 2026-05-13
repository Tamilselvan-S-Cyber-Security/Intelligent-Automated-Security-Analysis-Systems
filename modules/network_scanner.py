#!/usr/bin/env python3
"""
CyberWolf Network Scanner Module
Comprehensive DNS and Network Testing Tools
"""

import os
import socket
import subprocess
import requests
import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import whois
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any
import ipaddress
import re
import urllib.parse
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class NetworkScanner:
    """
    Comprehensive Network and DNS Scanner for CyberWolf
    """
    
    def __init__(self, target: str, timeout: int = 10, max_workers: int = 50):
        self.target = target
        self.timeout = timeout
        self.max_workers = max_workers
        self.results = {}
        
    def clean_target(self, target: str) -> str:
        """Clean and validate target input"""
        target = target.strip()
        if target.startswith(('http://', 'https://')):
            target = urllib.parse.urlparse(target).netloc
        return target
    
    def get_ip_address(self, domain: str) -> Dict[str, Any]:
        """Get IP address information for a domain"""
        try:
            domain = self.clean_target(domain)
            ip_info = {
                'domain': domain,
                'ips': [],
                'primary_ip': None,
                'status': 'success'
            }
            
            # Resolve domain to IP
            try:
                answers = dns.resolver.resolve(domain, 'A')
                for answer in answers:
                    ip_info['ips'].append(str(answer))
                if ip_info['ips']:
                    ip_info['primary_ip'] = ip_info['ips'][0]
            except Exception as e:
                ip_info['status'] = f'DNS resolution failed: {str(e)}'
                
            return ip_info
        except Exception as e:
            return {'domain': domain, 'status': f'Error: {str(e)}', 'ips': []}
    
    def ping_test(self, target: str) -> Dict[str, Any]:
        """Perform ping test"""
        try:
            target = self.clean_target(target)
            result = {
                'target': target,
                'status': 'unknown',
                'response_time': None,
                'packet_loss': None,
                'details': []
            }
            
            # Use system ping command
            if os.name == 'nt':  # Windows
                cmd = ['ping', '-n', '4', target]
            else:  # Linux/Mac
                cmd = ['ping', '-c', '4', target]
            
            try:
                output = subprocess.check_output(cmd, timeout=self.timeout, stderr=subprocess.STDOUT, text=True)
                result['details'] = output.split('\n')
                
                # Parse ping results
                if 'time=' in output or 'time<' in output:
                    result['status'] = 'success'
                    # Extract response time
                    time_match = re.search(r'time[=<>](\d+(?:\.\d+)?)', output)
                    if time_match:
                        result['response_time'] = float(time_match.group(1))
                else:
                    result['status'] = 'failed'
                    
            except subprocess.TimeoutExpired:
                result['status'] = 'timeout'
            except subprocess.CalledProcessError:
                result['status'] = 'failed'
                
            return result
        except Exception as e:
            return {'target': target, 'status': f'Error: {str(e)}'}
    
    def traceroute(self, target: str) -> Dict[str, Any]:
        """Perform traceroute"""
        try:
            target = self.clean_target(target)
            result = {
                'target': target,
                'hops': [],
                'status': 'unknown'
            }
            
            # Use system traceroute command
            if os.name == 'nt':  # Windows
                cmd = ['tracert', target]
            else:  # Linux/Mac
                cmd = ['traceroute', target]
            
            try:
                output = subprocess.check_output(cmd, timeout=self.timeout*2, stderr=subprocess.STDOUT, text=True)
                lines = output.split('\n')
                
                for line in lines:
                    if re.match(r'^\s*\d+', line):  # Lines starting with numbers
                        hop_info = self._parse_traceroute_line(line)
                        if hop_info:
                            result['hops'].append(hop_info)
                
                result['status'] = 'success' if result['hops'] else 'failed'
                
            except subprocess.TimeoutExpired:
                result['status'] = 'timeout'
            except subprocess.CalledProcessError:
                result['status'] = 'failed'
                
            return result
        except Exception as e:
            return {'target': target, 'status': f'Error: {str(e)}', 'hops': []}
    
    def _parse_traceroute_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse traceroute output line"""
        try:
            # Extract hop number, IP, and response time
            parts = line.strip().split()
            if len(parts) >= 2:
                hop_num = int(parts[0])
                ip = None
                hostname = None
                response_time = None
                
                # Extract IP and hostname
                for part in parts[1:]:
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', part):
                        ip = part
                    elif re.match(r'^\d+(?:\.\d+)?ms$', part):
                        response_time = float(part.replace('ms', ''))
                    elif not part.startswith('*') and '.' in part:
                        hostname = part
                
                return {
                    'hop': hop_num,
                    'ip': ip,
                    'hostname': hostname,
                    'response_time': response_time
                }
        except Exception:
            pass
        return None
    
    def dns_lookup(self, domain: str, record_type: str = 'A') -> Dict[str, Any]:
        """Perform DNS lookup for various record types"""
        try:
            domain = self.clean_target(domain)
            result = {
                'domain': domain,
                'record_type': record_type,
                'records': [],
                'status': 'success'
            }
            
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for answer in answers:
                    result['records'].append(str(answer))
            except dns.resolver.NXDOMAIN:
                result['status'] = 'NXDOMAIN'
            except dns.resolver.NoAnswer:
                result['status'] = 'NoAnswer'
            except Exception as e:
                result['status'] = f'Error: {str(e)}'
                
            return result
        except Exception as e:
            return {'domain': domain, 'record_type': record_type, 'status': f'Error: {str(e)}', 'records': []}
    
    def reverse_dns(self, ip: str) -> Dict[str, Any]:
        """Perform reverse DNS lookup"""
        try:
            result = {
                'ip': ip,
                'hostnames': [],
                'status': 'success'
            }
            
            try:
                reverse_name = dns.reversename.from_address(ip)
                answers = dns.resolver.resolve(reverse_name, 'PTR')
                for answer in answers:
                    result['hostnames'].append(str(answer))
            except Exception as e:
                result['status'] = f'Error: {str(e)}'
                
            return result
        except Exception as e:
            return {'ip': ip, 'status': f'Error: {str(e)}', 'hostnames': []}
    
    def find_subdomains(self, domain: str) -> Dict[str, Any]:
        """Find subdomains using various techniques"""
        try:
            domain = self.clean_target(domain)
            result = {
                'domain': domain,
                'subdomains': [],
                'techniques_used': [],
                'status': 'success'
            }
            
            # Technique 1: DNS bruteforce with common subdomains
            common_subdomains = [
                'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'stage',
                'api', 'cdn', 'static', 'img', 'images', 'media', 'support',
                'help', 'docs', 'wiki', 'forum', 'shop', 'store', 'app',
                'mobile', 'm', 'web', 'secure', 'login', 'auth', 'dashboard'
            ]
            
            found_subdomains = []
            for subdomain in common_subdomains:
                full_domain = f"{subdomain}.{domain}"
                try:
                    dns.resolver.resolve(full_domain, 'A')
                    found_subdomains.append(full_domain)
                except:
                    continue
            
            result['subdomains'].extend(found_subdomains)
            result['techniques_used'].append('DNS bruteforce')
            
            # Technique 2: Check for common DNS records
            common_records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            for record_type in common_records:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for answer in answers:
                        if hasattr(answer, 'target'):
                            target = str(answer.target)
                            if target.endswith(domain) and target != domain:
                                result['subdomains'].append(target)
                except:
                    continue
            
            result['techniques_used'].append('DNS records analysis')
            
            # Remove duplicates
            result['subdomains'] = list(set(result['subdomains']))
            
            return result
        except Exception as e:
            return {'domain': domain, 'status': f'Error: {str(e)}', 'subdomains': []}
    
    def find_shared_dns_servers(self, domain: str) -> Dict[str, Any]:
        """Find shared DNS servers"""
        try:
            domain = self.clean_target(domain)
            result = {
                'domain': domain,
                'dns_servers': [],
                'shared_servers': [],
                'status': 'success'
            }
            
            # Get DNS servers for the domain
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                for answer in answers:
                    result['dns_servers'].append(str(answer))
            except Exception as e:
                result['status'] = f'Error getting NS records: {str(e)}'
                return result
            
            # Check for shared DNS servers (this would require additional research)
            # For now, we'll return the DNS servers found
            result['shared_servers'] = result['dns_servers']
            
            return result
        except Exception as e:
            return {'domain': domain, 'status': f'Error: {str(e)}', 'dns_servers': []}
    
    def zone_transfer(self, domain: str) -> Dict[str, Any]:
        """Attempt zone transfer"""
        try:
            domain = self.clean_target(domain)
            result = {
                'domain': domain,
                'zone_data': [],
                'status': 'success',
                'vulnerable': False
            }
            
            # Get DNS servers
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                nameservers = [str(answer) for answer in answers]
            except Exception as e:
                result['status'] = f'Error getting nameservers: {str(e)}'
                return result
            
            # Attempt zone transfer on each nameserver
            for nameserver in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            result['zone_data'].append({
                                'name': str(name),
                                'type': str(rdataset.rdtype),
                                'data': str(rdataset)
                            })
                    result['vulnerable'] = True
                except Exception:
                    continue
            
            if not result['zone_data']:
                result['status'] = 'Zone transfer not allowed'
            
            return result
        except Exception as e:
            return {'domain': domain, 'status': f'Error: {str(e)}', 'zone_data': []}
    
    def whois_lookup(self, target: str) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        try:
            target = self.clean_target(target)
            result = {
                'target': target,
                'whois_data': {},
                'status': 'success'
            }
            
            try:
                w = whois.whois(target)
                result['whois_data'] = {
                    'domain_name': w.domain_name,
                    'registrar': w.registrar,
                    'creation_date': w.creation_date,
                    'expiration_date': w.expiration_date,
                    'updated_date': w.updated_date,
                    'status': w.status,
                    'name_servers': w.name_servers,
                    'emails': w.emails
                }
            except Exception as e:
                result['status'] = f'Error: {str(e)}'
                
            return result
        except Exception as e:
            return {'target': target, 'status': f'Error: {str(e)}', 'whois_data': {}}
    
    def ip_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get IP geolocation information"""
        try:
            result = {
                'ip': ip,
                'geolocation': {},
                'status': 'success'
            }
            
            # Use free IP geolocation API
            try:
                response = requests.get(f'http://ip-api.com/json/{ip}', timeout=self.timeout)
                if response.status_code == 200:
                    data = response.json()
                    result['geolocation'] = {
                        'country': data.get('country'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as')
                    }
                else:
                    result['status'] = f'API error: {response.status_code}'
            except Exception as e:
                result['status'] = f'Error: {str(e)}'
                
            return result
        except Exception as e:
            return {'ip': ip, 'status': f'Error: {str(e)}', 'geolocation': {}}
    
    def reverse_ip_lookup(self, ip: str) -> Dict[str, Any]:
        """Perform reverse IP lookup to find domains"""
        try:
            result = {
                'ip': ip,
                'domains': [],
                'status': 'success'
            }
            
            # This would typically require access to reverse IP databases
            # For now, we'll use a simple approach with reverse DNS
            reverse_dns_result = self.reverse_dns(ip)
            if reverse_dns_result['hostnames']:
                result['domains'].extend(reverse_dns_result['hostnames'])
            
            return result
        except Exception as e:
            return {'ip': ip, 'status': f'Error: {str(e)}', 'domains': []}
    
    def tcp_port_scan(self, target: str, ports: List[int] = None) -> Dict[str, Any]:
        """Perform TCP port scan"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
        
        try:
            target = self.clean_target(target)
            result = {
                'target': target,
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'status': 'success'
            }
            
            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result_code = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result_code == 0:
                        return port, 'open'
                    else:
                        return port, 'closed'
                except Exception:
                    return port, 'filtered'
            
            # Use ThreadPoolExecutor for concurrent scanning
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_port = {executor.submit(scan_port, port): port for port in ports}
                
                for future in as_completed(future_to_port):
                    port, status = future.result()
                    if status == 'open':
                        result['open_ports'].append(port)
                    elif status == 'closed':
                        result['closed_ports'].append(port)
                    else:
                        result['filtered_ports'].append(port)
            
            return result
        except Exception as e:
            return {'target': target, 'status': f'Error: {str(e)}', 'open_ports': []}
    
    def udp_port_scan(self, target: str, ports: List[int] = None) -> Dict[str, Any]:
        """Perform UDP port scan"""
        if ports is None:
            ports = [53, 67, 68, 69, 123, 161, 162, 389, 514, 520, 1194, 1434, 1701, 1812, 1813, 500, 4500]
        
        try:
            target = self.clean_target(target)
            result = {
                'target': target,
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'status': 'success'
            }
            
            def scan_udp_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.timeout)
                    
                    # Send empty packet
                    sock.sendto(b'', (target, port))
                    
                    try:
                        data, addr = sock.recvfrom(1024)
                        sock.close()
                        return port, 'open'
                    except socket.timeout:
                        sock.close()
                        return port, 'open|filtered'
                except Exception:
                    return port, 'filtered'
            
            # Use ThreadPoolExecutor for concurrent scanning
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_port = {executor.submit(scan_udp_port, port): port for port in ports}
                
                for future in as_completed(future_to_port):
                    port, status = future.result()
                    if 'open' in status:
                        result['open_ports'].append(port)
                    elif 'closed' in status:
                        result['closed_ports'].append(port)
                    else:
                        result['filtered_ports'].append(port)
            
            return result
        except Exception as e:
            return {'target': target, 'status': f'Error: {str(e)}', 'open_ports': []}
    
    def subnet_lookup(self, ip: str, mask: int = 24) -> Dict[str, Any]:
        """Perform subnet analysis"""
        try:
            result = {
                'network': f"{ip}/{mask}",
                'subnet_info': {},
                'hosts': [],
                'status': 'success'
            }
            
            try:
                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                result['subnet_info'] = {
                    'network_address': str(network.network_address),
                    'broadcast_address': str(network.broadcast_address),
                    'netmask': str(network.netmask),
                    'num_addresses': network.num_addresses,
                    'num_hosts': network.num_addresses - 2
                }
                
                # Generate list of hosts (limited to first 50 for performance)
                for i, host in enumerate(network.hosts()):
                    if i >= 50:  # Limit to first 50 hosts
                        break
                    result['hosts'].append(str(host))
                    
            except Exception as e:
                result['status'] = f'Error: {str(e)}'
                
            return result
        except Exception as e:
            return {'network': f"{ip}/{mask}", 'status': f'Error: {str(e)}', 'subnet_info': {}}
    
    def asn_lookup(self, ip: str) -> Dict[str, Any]:
        """Perform ASN lookup"""
        try:
            result = {
                'ip': ip,
                'asn_info': {},
                'status': 'success'
            }
            
            # Use IP geolocation API which includes ASN info
            geo_result = self.ip_geolocation(ip)
            if geo_result['status'] == 'success' and geo_result['geolocation'].get('as'):
                as_info = geo_result['geolocation']['as']
                # Parse AS information (format: "AS12345 Organization Name")
                as_match = re.match(r'AS(\d+)\s+(.+)', as_info)
                if as_match:
                    result['asn_info'] = {
                        'asn': as_match.group(1),
                        'organization': as_match.group(2),
                        'isp': geo_result['geolocation'].get('isp'),
                        'org': geo_result['geolocation'].get('org')
                    }
            
            return result
        except Exception as e:
            return {'ip': ip, 'status': f'Error: {str(e)}', 'asn_info': {}}
    
    def banner_grabbing(self, target: str, ports: List[int] = None) -> Dict[str, Any]:
        """Perform banner grabbing on open ports"""
        if ports is None:
            ports = [21, 22, 23, 25, 80, 443, 3306, 5432, 8080, 8443]
        
        try:
            target = self.clean_target(target)
            result = {
                'target': target,
                'banners': {},
                'status': 'success'
            }
            
            def grab_banner(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((target, port))
                    
                    # Send common probes
                    probes = [
                        b'\r\n',
                        b'HEAD / HTTP/1.0\r\n\r\n',
                        b'GET / HTTP/1.0\r\n\r\n'
                    ]
                    
                    banner = ""
                    for probe in probes:
                        try:
                            sock.send(probe)
                            response = sock.recv(1024)
                            if response:
                                banner += response.decode('utf-8', errors='ignore')
                        except:
                            continue
                    
                    sock.close()
                    return port, banner.strip() if banner else "No banner"
                except Exception as e:
                    return port, f"Error: {str(e)}"
            
            # Use ThreadPoolExecutor for concurrent banner grabbing
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_port = {executor.submit(grab_banner, port): port for port in ports}
                
                for future in as_completed(future_to_port):
                    port, banner = future.result()
                    result['banners'][port] = banner
            
            return result
        except Exception as e:
            return {'target': target, 'status': f'Error: {str(e)}', 'banners': {}}
    
    def http_headers(self, url: str) -> Dict[str, Any]:
        """Extract HTTP headers"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
            
            result = {
                'url': url,
                'headers': {},
                'status_code': None,
                'server_info': {},
                'security_headers': {},
                'status': 'success'
            }
            
            try:
                response = requests.get(url, timeout=self.timeout, allow_redirects=True)
                result['status_code'] = response.status_code
                result['headers'] = dict(response.headers)
                
                # Extract server information
                result['server_info'] = {
                    'server': response.headers.get('Server'),
                    'powered_by': response.headers.get('X-Powered-By'),
                    'content_type': response.headers.get('Content-Type'),
                    'content_length': response.headers.get('Content-Length')
                }
                
                # Check for security headers
                security_headers = [
                    'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options',
                    'X-XSS-Protection', 'Content-Security-Policy', 'Referrer-Policy',
                    'Permissions-Policy', 'X-Permitted-Cross-Domain-Policies'
                ]
                
                for header in security_headers:
                    if header in response.headers:
                        result['security_headers'][header] = response.headers[header]
                
            except Exception as e:
                result['status'] = f'Error: {str(e)}'
                
            return result
        except Exception as e:
            return {'url': url, 'status': f'Error: {str(e)}', 'headers': {}}
    
    def extract_page_links(self, url: str) -> Dict[str, Any]:
        """Extract links from a web page"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
            
            result = {
                'url': url,
                'links': [],
                'internal_links': [],
                'external_links': [],
                'status': 'success'
            }
            
            try:
                response = requests.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    # Extract all links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        if href.startswith(('http://', 'https://')):
                            result['links'].append(href)
                            if url in href:
                                result['internal_links'].append(href)
                            else:
                                result['external_links'].append(href)
                        elif href.startswith('/'):
                            # Relative link
                            full_url = urllib.parse.urljoin(url, href)
                            result['links'].append(full_url)
                            result['internal_links'].append(full_url)
                
            except Exception as e:
                result['status'] = f'Error: {str(e)}'
                
            return result
        except Exception as e:
            return {'url': url, 'status': f'Error: {str(e)}', 'links': []}
    
    def reverse_analytics_search(self, domain: str) -> Dict[str, Any]:
        """Search for analytics and tracking codes"""
        try:
            domain = self.clean_target(domain)
            result = {
                'domain': domain,
                'analytics_services': [],
                'tracking_codes': [],
                'status': 'success'
            }
            
            # Common analytics services to search for
            analytics_patterns = {
                'Google Analytics': [r'UA-\d+-\d+', r'G-[A-Z0-9]+'],
                'Google Tag Manager': [r'GTM-[A-Z0-9]+'],
                'Facebook Pixel': [r'\d{15}'],
                'Hotjar': [r'hjid:\d+'],
                'Mixpanel': [r'mixpanel\.init\([\'"][a-zA-Z0-9]+\'"]'],
                'Segment': [r'analytics\.load\([\'"][a-zA-Z0-9]+\'"]'],
                'Piwik/Matomo': [r'piwik\.js', r'matomo\.js'],
                'Crazy Egg': [r'cetrk\.com'],
                'Optimizely': [r'optimizely\.com'],
                'VWO': [r'visualwebsiteoptimizer\.com']
            }
            
            try:
                url = f'http://{domain}'
                response = requests.get(url, timeout=self.timeout)
                content = response.text.lower()
                
                for service, patterns in analytics_patterns.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        if matches:
                            result['analytics_services'].append(service)
                            result['tracking_codes'].extend(matches)
                
                # Remove duplicates
                result['tracking_codes'] = list(set(result['tracking_codes']))
                result['analytics_services'] = list(set(result['analytics_services']))
                
            except Exception as e:
                result['status'] = f'Error: {str(e)}'
                
            return result
        except Exception as e:
            return {'domain': domain, 'status': f'Error: {str(e)}', 'analytics_services': []}
    
    def subdomain_path_traversal(self, domain: str) -> Dict[str, Any]:
        """
        Perform subdomain path traversal to discover exposed directories and files
        """
        try:
            domain = self.clean_target(domain)
            result = {
                'domain': domain,
                'scan_time': datetime.now().isoformat(),
                'subdomains': [],
                'exposed_paths': [],
                'vulnerable_paths': [],
                'status': 'success',
                'summary': {}
            }
            
            # Common subdomain patterns
            common_subdomains = [
                'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging',
                'api', 'cdn', 'static', 'img', 'images', 'assets', 'media',
                'support', 'help', 'docs', 'documentation', 'wiki', 'forum',
                'shop', 'store', 'app', 'webmail', 'remote', 'vpn', 'portal',
                'secure', 'ssl', 'ns1', 'ns2', 'mx1', 'mx2', 'smtp', 'pop',
                'imap', 'webdisk', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
                'm', 'mobile', 'wap', 'web', 'site', 'sites', 'demo', 'beta'
            ]
            
            # Common directory traversal paths to test
            traversal_paths = [
                '../', '..\\', '..%2f', '..%5c', '..%255c', '..%252f',
                '....//', '....\\\\', '..%c0%af', '..%c1%9c', '..%c0%9v',
                '..%c0%qf', '..%c1%8s', '..%c0%80', '..%c0%af', '..%c0%9v',
                '..%c0%qf', '..%c1%8s', '..%c0%80', '..%c0%af', '..%c0%9v'
            ]
            
            # Common sensitive directories and files
            sensitive_paths = [
                'admin', 'administrator', 'adm', 'root', 'user', 'users',
                'login', 'logon', 'signin', 'auth', 'authentication',
                'config', 'configuration', 'conf', 'settings', 'setup',
                'install', 'installation', 'backup', 'backups', 'bak',
                'db', 'database', 'sql', 'mysql', 'postgresql', 'oracle',
                'logs', 'log', 'tmp', 'temp', 'cache', 'session',
                'private', 'secret', 'hidden', 'internal', 'intranet',
                'dev', 'development', 'test', 'testing', 'staging',
                'git', 'svn', 'cvs', 'ftp', 'ssh', 'telnet',
                'phpinfo.php', 'info.php', 'test.php', 'debug.php',
                '.env', '.git', '.svn', '.htaccess', 'web.config',
                'robots.txt', 'sitemap.xml', 'crossdomain.xml'
            ]
            
            discovered_subdomains = []
            exposed_paths = []
            vulnerable_paths = []
            
            # Test common subdomains
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                subdomain_futures = []
                
                for sub in common_subdomains:
                    subdomain = f"{sub}.{domain}"
                    future = executor.submit(self._test_subdomain_paths, subdomain, traversal_paths, sensitive_paths)
                    subdomain_futures.append((subdomain, future))
                
                # Process results
                for subdomain, future in subdomain_futures:
                    try:
                        sub_result = future.result(timeout=self.timeout)
                        if sub_result['accessible']:
                            discovered_subdomains.append(subdomain)
                            exposed_paths.extend(sub_result['exposed_paths'])
                            vulnerable_paths.extend(sub_result['vulnerable_paths'])
                    except Exception as e:
                        logger.debug(f"Subdomain {subdomain} test failed: {str(e)}")
            
            # Test main domain paths
            main_domain_result = self._test_subdomain_paths(domain, traversal_paths, sensitive_paths)
            if main_domain_result['accessible']:
                exposed_paths.extend(main_domain_result['exposed_paths'])
                vulnerable_paths.extend(main_domain_result['vulnerable_paths'])
            
            # Remove duplicates
            exposed_paths = list(set(exposed_paths))
            vulnerable_paths = list(set(vulnerable_paths))
            
            result['subdomains'] = discovered_subdomains
            result['exposed_paths'] = exposed_paths
            result['vulnerable_paths'] = vulnerable_paths
            
            # Generate summary
            result['summary'] = {
                'total_subdomains_found': len(discovered_subdomains),
                'total_exposed_paths': len(exposed_paths),
                'total_vulnerable_paths': len(vulnerable_paths),
                'risk_level': self._calculate_risk_level(len(vulnerable_paths), len(exposed_paths))
            }
            
            return result
            
        except Exception as e:
            return {
                'domain': domain,
                'status': f'Error: {str(e)}',
                'subdomains': [],
                'exposed_paths': [],
                'vulnerable_paths': [],
                'summary': {}
            }
    
    def _test_subdomain_paths(self, subdomain: str, traversal_paths: List[str], sensitive_paths: List[str]) -> Dict[str, Any]:
        """
        Test individual subdomain for path traversal vulnerabilities
        """
        result = {
            'subdomain': subdomain,
            'accessible': False,
            'exposed_paths': [],
            'vulnerable_paths': [],
            'status': 'unknown'
        }
        
        try:
            # Test if subdomain is accessible
            url = f'http://{subdomain}'
            response = requests.get(url, timeout=self.timeout, allow_redirects=False)
            
            if response.status_code < 400:  # Accessible
                result['accessible'] = True
                result['status'] = 'accessible'
                
                # Test traversal paths
                for path in traversal_paths:
                    try:
                        traversal_url = f"{url}/{path}"
                        traversal_response = requests.get(traversal_url, timeout=self.timeout, allow_redirects=False)
                        
                        if traversal_response.status_code == 200:
                            # Check if response contains directory listing or sensitive info
                            content = traversal_response.text.lower()
                            if any(indicator in content for indicator in ['directory listing', 'index of', 'parent directory', 'root directory']):
                                result['vulnerable_paths'].append(f"{path} - Directory listing exposed")
                            elif len(content) > 1000:  # Large response might indicate successful traversal
                                result['vulnerable_paths'].append(f"{path} - Large response, potential traversal")
                                
                    except Exception as e:
                        logger.debug(f"Traversal path {path} test failed: {str(e)}")
                
                # Test sensitive paths
                for path in sensitive_paths:
                    try:
                        sensitive_url = f"{url}/{path}"
                        sensitive_response = requests.get(sensitive_url, timeout=self.timeout, allow_redirects=False)
                        
                        if sensitive_response.status_code == 200:
                            result['exposed_paths'].append(f"{path} - Accessible")
                        elif sensitive_response.status_code in [301, 302, 307, 308]:
                            result['exposed_paths'].append(f"{path} - Redirects to: {sensitive_response.headers.get('Location', 'Unknown')}")
                            
                    except Exception as e:
                        logger.debug(f"Sensitive path {path} test failed: {str(e)}")
                        
        except Exception as e:
            result['status'] = f'Error: {str(e)}'
            
        return result
    
    def _calculate_risk_level(self, vulnerable_count: int, exposed_count: int) -> str:
        """
        Calculate risk level based on findings
        """
        if vulnerable_count > 5 or exposed_count > 10:
            return 'HIGH'
        elif vulnerable_count > 2 or exposed_count > 5:
            return 'MEDIUM'
        elif vulnerable_count > 0 or exposed_count > 0:
            return 'LOW'
        else:
            return 'NONE'
    
    def comprehensive_scan(self, target: str) -> Dict[str, Any]:
        """Perform comprehensive network and DNS scan"""
        try:
            target = self.clean_target(target)
            result = {
                'target': target,
                'scan_time': datetime.now().isoformat(),
                'ip_info': {},
                'dns_info': {},
                'network_info': {},
                'security_info': {},
                'status': 'success'
            }
            
            # Get IP information
            result['ip_info'] = self.get_ip_address(target)
            
            # Get primary IP for additional scans
            primary_ip = result['ip_info'].get('primary_ip')
            
            if primary_ip:
                # DNS lookups
                result['dns_info'] = {
                    'a_record': self.dns_lookup(target, 'A'),
                    'aaaa_record': self.dns_lookup(target, 'AAAA'),
                    'mx_record': self.dns_lookup(target, 'MX'),
                    'ns_record': self.dns_lookup(target, 'NS'),
                    'txt_record': self.dns_lookup(target, 'TXT'),
                    'reverse_dns': self.reverse_dns(primary_ip),
                    'subdomains': self.find_subdomains(target),
                    'zone_transfer': self.zone_transfer(target)
                }
                
                # Network information
                result['network_info'] = {
                    'ping': self.ping_test(target),
                    'traceroute': self.traceroute(target),
                    'tcp_scan': self.tcp_port_scan(target),
                    'udp_scan': self.udp_port_scan(target),
                    'banner_grab': self.banner_grabbing(target),
                    'geolocation': self.ip_geolocation(primary_ip),
                    'asn': self.asn_lookup(primary_ip),
                    'subnet': self.subnet_lookup(primary_ip)
                }
                
                # Security information
                result['security_info'] = {
                    'http_headers': self.http_headers(target),
                    'page_links': self.extract_page_links(target),
                    'analytics': self.reverse_analytics_search(target),
                    'whois': self.whois_lookup(target),
                    'subdomain_path_traversal': self.subdomain_path_traversal(target)
                }
            
            return result
        except Exception as e:
            return {'target': target, 'status': f'Error: {str(e)}'}


