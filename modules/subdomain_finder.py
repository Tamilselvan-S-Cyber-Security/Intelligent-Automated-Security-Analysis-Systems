#!/usr/bin/env python3
"""
CyberWolf Subdomain Finder Module
Advanced subdomain enumeration and directory traversal tools
"""

import requests
import dns.resolver
import dns.reversename
import threading
import time
import json
import re
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urljoin, urlparse
import socket
import ssl
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class SubdomainFinder:
    """
    Advanced Subdomain Finder with Directory Traversal and Information Gathering
    """
    
    def __init__(self, target: str, timeout: int = 10, max_workers: int = 100):
        self.target = target.strip()
        self.timeout = timeout
        self.max_workers = max_workers
        self.results = {
            'subdomains': set(),
            'directories': set(),
            'files': set(),
            'techniques_used': [],
            'scan_time': None,
            'status': 'pending'
        }
        
        # Common subdomain wordlists
        self.subdomain_wordlist = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'stage', 'api', 'cdn',
            'static', 'img', 'images', 'media', 'support', 'help', 'docs', 'wiki', 'forum',
            'shop', 'store', 'app', 'mobile', 'm', 'web', 'secure', 'login', 'auth',
            'dashboard', 'panel', 'cpanel', 'whm', 'ns1', 'ns2', 'dns', 'mx', 'smtp',
            'pop', 'imap', 'vpn', 'proxy', 'gateway', 'router', 'firewall', 'backup',
            'db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'cache', 'loadbalancer',
            'lb', 'monitor', 'stats', 'analytics', 'tracking', 'ads', 'advertising',
            'billing', 'payment', 'checkout', 'cart', 'order', 'customer', 'user',
            'member', 'account', 'profile', 'settings', 'config', 'setup', 'install',
            'update', 'upgrade', 'maintenance', 'status', 'health', 'ping', 'monitor',
            'alert', 'notification', 'log', 'logs', 'debug', 'error', 'exception',
            'crash', 'report', 'feedback', 'contact', 'about', 'team', 'careers',
            'news', 'press', 'media', 'pr', 'marketing', 'sales', 'support', 'helpdesk',
            'ticket', 'issue', 'bug', 'feature', 'roadmap', 'changelog', 'version',
            'release', 'beta', 'alpha', 'staging', 'production', 'live', 'demo',
            'sandbox', 'playground', 'test', 'testing', 'qa', 'quality', 'assurance'
        ]
        
        # Common directory wordlist
        self.directory_wordlist = [
            'admin', 'administrator', 'adm', 'panel', 'cpanel', 'whm', 'webmail',
            'mail', 'email', 'ftp', 'sftp', 'ssh', 'telnet', 'remote', 'vpn',
            'api', 'rest', 'graphql', 'soap', 'xmlrpc', 'rpc', 'ws', 'websocket',
            'cdn', 'static', 'assets', 'images', 'img', 'css', 'js', 'fonts',
            'uploads', 'files', 'downloads', 'media', 'videos', 'audio', 'docs',
            'documents', 'pdf', 'word', 'excel', 'powerpoint', 'backup', 'backups',
            'db', 'database', 'sql', 'mysql', 'postgres', 'mongodb', 'redis',
            'cache', 'temp', 'tmp', 'log', 'logs', 'error', 'debug', 'test',
            'testing', 'dev', 'development', 'staging', 'beta', 'alpha', 'demo',
            'sandbox', 'playground', 'config', 'configuration', 'settings',
            'setup', 'install', 'installation', 'update', 'upgrade', 'patch',
            'maintenance', 'status', 'health', 'monitor', 'monitoring', 'stats',
            'statistics', 'analytics', 'tracking', 'report', 'reports', 'dashboard',
            'control', 'management', 'manage', 'admin', 'user', 'users', 'member',
            'members', 'account', 'accounts', 'profile', 'profiles', 'settings',
            'preferences', 'options', 'configuration', 'config', 'system',
            'server', 'servers', 'host', 'hosts', 'node', 'nodes', 'cluster',
            'clusters', 'loadbalancer', 'lb', 'proxy', 'gateway', 'router',
            'firewall', 'security', 'auth', 'authentication', 'login', 'logout',
            'register', 'signup', 'signin', 'password', 'reset', 'forgot',
            'verify', 'confirmation', 'activate', 'activation', 'token',
            'session', 'sessions', 'cookie', 'cookies', 'cache', 'caching',
            'storage', 'file', 'files', 'upload', 'download', 'share', 'public',
            'private', 'secure', 'protected', 'hidden', 'secret', 'internal',
            'external', 'api', 'rest', 'graphql', 'soap', 'xmlrpc', 'rpc',
            'ws', 'websocket', 'sse', 'webhook', 'callback', 'redirect',
            'forward', 'proxy', 'gateway', 'router', 'firewall', 'security'
        ]
        
        # Common file extensions
        self.file_extensions = [
            '.php', '.html', '.htm', '.js', '.css', '.xml', '.json', '.txt',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip',
            '.rar', '.tar', '.gz', '.7z', '.sql', '.bak', '.backup', '.old',
            '.tmp', '.temp', '.log', '.ini', '.conf', '.config', '.env',
            '.htaccess', '.htpasswd', '.git', '.svn', '.cvs', '.ds_store',
            '.robots.txt', '.sitemap.xml', '.crossdomain.xml', '.clientaccesspolicy.xml'
        ]
    
    def clean_target(self, target: str) -> str:
        """Clean and validate target input"""
        target = target.strip()
        if target.startswith(('http://', 'https://')):
            target = urlparse(target).netloc
        return target
    
    def dns_bruteforce(self) -> Set[str]:
        """DNS bruteforce subdomain enumeration"""
        found_subdomains = set()
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{self.target}"
                dns.resolver.resolve(full_domain, 'A')
                return full_domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subdomain = {
                executor.submit(check_subdomain, subdomain): subdomain 
                for subdomain in self.subdomain_wordlist
            }
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    found_subdomains.add(result)
        
        self.results['techniques_used'].append('DNS Bruteforce')
        return found_subdomains
    
    def certificate_transparency(self) -> Set[str]:
        """Find subdomains using Certificate Transparency logs"""
        found_subdomains = set()
        
        try:
            # Use crt.sh API
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        # Extract subdomains from certificate names
                        names = name_value.split('\n')
                        for name in names:
                            name = name.strip()
                            if name.endswith(f'.{self.target}') and name != self.target:
                                found_subdomains.add(name)
            
            # Use Censys API (if available)
            # This would require API key
            pass
            
        except Exception as e:
            logger.error(f"Certificate transparency error: {e}")
        
        self.results['techniques_used'].append('Certificate Transparency')
        return found_subdomains
    
    def search_engines(self) -> Set[str]:
        """Find subdomains using search engines"""
        found_subdomains = set()
        
        search_engines = [
            f"https://www.google.com/search?q=site:*.{self.target}",
            f"https://www.bing.com/search?q=site:*.{self.target}",
            f"https://search.yahoo.com/search?p=site:*.{self.target}"
        ]
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        for url in search_engines:
            try:
                response = requests.get(url, headers=headers, timeout=self.timeout)
                if response.status_code == 200:
                    # Extract subdomains from search results
                    pattern = rf'[a-zA-Z0-9.-]+\.{re.escape(self.target)}'
                    matches = re.findall(pattern, response.text)
                    for match in matches:
                        if match != self.target:
                            found_subdomains.add(match)
            except Exception as e:
                logger.error(f"Search engine error: {e}")
        
        self.results['techniques_used'].append('Search Engines')
        return found_subdomains
    
    def dns_zone_transfer(self) -> Set[str]:
        """Attempt DNS zone transfer"""
        found_subdomains = set()
        
        try:
            # Get nameservers
            answers = dns.resolver.resolve(self.target, 'NS')
            nameservers = [str(answer) for answer in answers]
            
            for nameserver in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(nameserver, self.target))
                    for name, node in zone.nodes.items():
                        name_str = str(name)
                        if name_str != '@' and name_str != self.target:
                            full_domain = f"{name_str}.{self.target}"
                            found_subdomains.add(full_domain)
                except:
                    continue
        except Exception as e:
            logger.error(f"Zone transfer error: {e}")
        
        self.results['techniques_used'].append('DNS Zone Transfer')
        return found_subdomains
    
    def reverse_dns_scan(self) -> Set[str]:
        """Reverse DNS scanning for subdomains"""
        found_subdomains = set()
        
        try:
            # Get IP range for the target
            ip_info = dns.resolver.resolve(self.target, 'A')
            if ip_info:
                primary_ip = str(ip_info[0])
                # Scan nearby IPs for reverse DNS
                ip_parts = primary_ip.split('.')
                base_ip = '.'.join(ip_parts[:-1])
                
                for i in range(1, 255):
                    test_ip = f"{base_ip}.{i}"
                    try:
                        reverse_name = dns.reversename.from_address(test_ip)
                        answers = dns.resolver.resolve(reverse_name, 'PTR')
                        for answer in answers:
                            hostname = str(answer)
                            if hostname.endswith(f'.{self.target}'):
                                found_subdomains.add(hostname)
                    except:
                        continue
        except Exception as e:
            logger.error(f"Reverse DNS scan error: {e}")
        
        self.results['techniques_used'].append('Reverse DNS Scan')
        return found_subdomains
    
    def web_crawling(self) -> Set[str]:
        """Web crawling to find subdomains"""
        found_subdomains = set()
        
        try:
            # Crawl main domain
            urls_to_crawl = [f"http://{self.target}", f"https://{self.target}"]
            
            for url in urls_to_crawl:
                try:
                    response = requests.get(url, timeout=self.timeout)
                    if response.status_code == 200:
                        # Extract subdomains from HTML content
                        pattern = rf'[a-zA-Z0-9.-]+\.{re.escape(self.target)}'
                        matches = re.findall(pattern, response.text)
                        for match in matches:
                            if match != self.target:
                                found_subdomains.add(match)
                        
                        # Extract from links
                        link_pattern = r'href=["\']([^"\']+)["\']'
                        links = re.findall(link_pattern, response.text)
                        for link in links:
                            if self.target in link:
                                parsed = urlparse(link)
                                if parsed.netloc and parsed.netloc != self.target:
                                    found_subdomains.add(parsed.netloc)
                except:
                    continue
        except Exception as e:
            logger.error(f"Web crawling error: {e}")
        
        self.results['techniques_used'].append('Web Crawling')
        return found_subdomains
    
    def directory_traversal(self, base_url: str) -> Dict[str, Any]:
        """Directory and file traversal"""
        found_items = {
            'directories': set(),
            'files': set(),
            'accessible_urls': set()
        }
        
        def check_path(path):
            url = urljoin(base_url, path)
            try:
                response = requests.get(url, timeout=self.timeout, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    if path.endswith('/'):
                        found_items['directories'].add(path)
                    else:
                        found_items['files'].add(path)
                    found_items['accessible_urls'].add(url)
                    return True
            except:
                pass
            return False
        
        # Check directories
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            directory_futures = {
                executor.submit(check_path, f"{dir}/"): dir 
                for dir in self.directory_wordlist
            }
            
            for future in as_completed(directory_futures):
                future.result()
        
        # Check files
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            file_futures = {
                executor.submit(check_path, f"{dir}{ext}"): f"{dir}{ext}"
                for dir in self.directory_wordlist[:50]  # Limit for performance
                for ext in self.file_extensions[:10]     # Limit for performance
            }
            
            for future in as_completed(file_futures):
                future.result()
        
        return found_items
    
    def gather_subdomain_info(self, subdomain: str) -> Dict[str, Any]:
        """Gather comprehensive information about a subdomain"""
        info = {
            'subdomain': subdomain,
            'ip_addresses': [],
            'http_status': None,
            'https_status': None,
            'server_info': {},
            'technologies': [],
            'headers': {},
            'ssl_info': {},
            'ports': [],
            'directories': [],
            'files': []
        }
        
        try:
            # DNS resolution
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                info['ip_addresses'] = [str(answer) for answer in answers]
            except:
                pass
            
            # HTTP/HTTPS check
            for protocol in ['http', 'https']:
                url = f"{protocol}://{subdomain}"
                try:
                    response = requests.get(url, timeout=self.timeout, allow_redirects=True)
                    if protocol == 'http':
                        info['http_status'] = response.status_code
                    else:
                        info['https_status'] = response.status_code
                    
                    info['headers'] = dict(response.headers)
                    
                    # Server information
                    info['server_info'] = {
                        'server': response.headers.get('Server'),
                        'powered_by': response.headers.get('X-Powered-By'),
                        'content_type': response.headers.get('Content-Type')
                    }
                    
                    # Technology detection
                    content = response.text.lower()
                    technologies = []
                    
                    if 'wordpress' in content:
                        technologies.append('WordPress')
                    if 'drupal' in content:
                        technologies.append('Drupal')
                    if 'joomla' in content:
                        technologies.append('Joomla')
                    if 'apache' in response.headers.get('Server', '').lower():
                        technologies.append('Apache')
                    if 'nginx' in response.headers.get('Server', '').lower():
                        technologies.append('Nginx')
                    if 'php' in response.headers.get('X-Powered-By', '').lower():
                        technologies.append('PHP')
                    
                    info['technologies'] = technologies
                    
                except:
                    pass
            
            # SSL information
            if info['ip_addresses']:
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((subdomain, 443), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=subdomain) as ssock:
                            cert = ssock.getpeercert()
                            info['ssl_info'] = {
                                'subject': dict(x[0] for x in cert['subject']),
                                'issuer': dict(x[0] for x in cert['issuer']),
                                'version': cert['version'],
                                'serial_number': cert['serialNumber'],
                                'not_before': cert['notBefore'],
                                'not_after': cert['notAfter']
                            }
                except:
                    pass
            
            # Port scanning
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
            open_ports = []
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((subdomain, port))
                    sock.close()
                    if result == 0:
                        open_ports.append(port)
                except:
                    pass
            
            info['ports'] = open_ports
            
        except Exception as e:
            logger.error(f"Error gathering info for {subdomain}: {e}")
        
        return info
    
    def comprehensive_scan(self) -> Dict[str, Any]:
        """Perform comprehensive subdomain enumeration and analysis"""
        start_time = datetime.now()
        
        # Collect subdomains using all techniques
        all_subdomains = set()
        
        # DNS bruteforce
        dns_subdomains = self.dns_bruteforce()
        all_subdomains.update(dns_subdomains)
        
        # Certificate transparency
        ct_subdomains = self.certificate_transparency()
        all_subdomains.update(ct_subdomains)
        
        # Search engines
        se_subdomains = self.search_engines()
        all_subdomains.update(se_subdomains)
        
        # DNS zone transfer
        zt_subdomains = self.dns_zone_transfer()
        all_subdomains.update(zt_subdomains)
        
        # Reverse DNS scan
        rdns_subdomains = self.reverse_dns_scan()
        all_subdomains.update(rdns_subdomains)
        
        # Web crawling
        wc_subdomains = self.web_crawling()
        all_subdomains.update(wc_subdomains)
        
        # Gather information for each subdomain
        subdomain_info = {}
        for subdomain in all_subdomains:
            info = self.gather_subdomain_info(subdomain)
            subdomain_info[subdomain] = info
        
        # Directory traversal for main domain
        main_domain_traversal = self.directory_traversal(f"http://{self.target}")
        
        # Compile results
        self.results.update({
            'subdomains': all_subdomains,
            'subdomain_info': subdomain_info,
            'directories': main_domain_traversal['directories'],
            'files': main_domain_traversal['files'],
            'accessible_urls': main_domain_traversal['accessible_urls'],
            'scan_time': (datetime.now() - start_time).total_seconds(),
            'status': 'completed'
        })
        
        return self.results
    
    def export_results(self, format: str = 'json') -> str:
        """Export results in various formats"""
        if format == 'json':
            # Convert sets to lists for JSON serialization
            export_data = {
                'target': self.target,
                'scan_time': self.results['scan_time'],
                'techniques_used': self.results['techniques_used'],
                'subdomains': list(self.results['subdomains']),
                'subdomain_info': self.results.get('subdomain_info', {}),
                'directories': list(self.results.get('directories', set())),
                'files': list(self.results.get('files', set())),
                'accessible_urls': list(self.results.get('accessible_urls', set()))
            }
            return json.dumps(export_data, indent=2)
        
        elif format == 'txt':
            output = []
            output.append(f"Subdomain Finder Results for {self.target}")
            output.append("=" * 50)
            output.append(f"Scan Time: {self.results['scan_time']} seconds")
            output.append(f"Techniques Used: {', '.join(self.results['techniques_used'])}")
            output.append("")
            output.append("SUBDOMAINS:")
            for subdomain in sorted(self.results['subdomains']):
                output.append(f"  - {subdomain}")
            output.append("")
            output.append("DIRECTORIES:")
            for directory in sorted(self.results.get('directories', set())):
                output.append(f"  - {directory}")
            output.append("")
            output.append("FILES:")
            for file in sorted(self.results.get('files', set())):
                output.append(f"  - {file}")
            return "\n".join(output)
        
        else:
            raise ValueError(f"Unsupported format: {format}")
