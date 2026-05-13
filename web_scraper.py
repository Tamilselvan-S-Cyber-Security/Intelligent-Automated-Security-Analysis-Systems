"""
Web scraper module for the Cyber Wolf Security Analyzer.
Uses trafilatura to extract clean text content from websites for security analysis.
Also supports crawling multiple pages of a website to build a comprehensive clone.
"""

import trafilatura
from urllib.parse import urlparse, urljoin
import requests
from typing import Dict, List, Tuple, Any, Set
import re
import logging
import time
from bs4 import BeautifulSoup

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_website_text_content(url: str) -> str:
    """
    Extract main text content from a website using trafilatura.
    
    Args:
        url (str): The URL to scrape
        
    Returns:
        str: The extracted text content
    """
    try:
        # Send a request to the website
        downloaded = trafilatura.fetch_url(url)
        text = trafilatura.extract(downloaded)
        
        if not text:
            logger.warning(f"No text content extracted from {url}")
            return f"No text content could be extracted from {url}. The page might be protected, use JavaScript, or contain no main content."
        
        return text
    except Exception as e:
        logger.error(f"Error extracting content from {url}: {str(e)}")
        return f"Error extracting content: {str(e)}"

def extract_urls(url: str, max_urls: int = 10) -> List[str]:
    """
    Extract URLs from a webpage for mapping attack surface.
    
    Args:
        url (str): The base URL to extract links from
        max_urls (int): Maximum number of URLs to extract
        
    Returns:
        List[str]: List of extracted URLs
    """
    try:
        # Parse the base URL to get the domain
        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc
        
        # Get the page content
        response = requests.get(url, timeout=10)
        content = response.text
        
        # Extract URLs using regex
        url_pattern = re.compile(r'href=["\'](https?://[^"\'>]+|/[^"\'>]+)["\']')
        all_urls = url_pattern.findall(content)
        
        # Process and filter URLs
        processed_urls = []
        for extracted_url in all_urls:
            # Handle relative URLs
            if extracted_url.startswith('/'):
                full_url = f"{parsed_url.scheme}://{base_domain}{extracted_url}"
            else:
                full_url = extracted_url
            
            # Only include URLs from the same domain
            if urlparse(full_url).netloc == base_domain:
                processed_urls.append(full_url)
                
            # Limit the number of URLs
            if len(processed_urls) >= max_urls:
                break
                
        return list(set(processed_urls))  # Remove duplicates
        
    except Exception as e:
        logger.error(f"Error extracting URLs from {url}: {str(e)}")
        return []

def identify_input_fields(url: str) -> List[Dict[str, Any]]:
    """
    Identify potential input fields and forms on a webpage that could be attack vectors.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        List[Dict[str, Any]]: List of identified input fields with their attributes
    """
    try:
        # Get the page content
        response = requests.get(url, timeout=10)
        content = response.text
        
        # Extract form tags
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL)
        forms = form_pattern.findall(content)
        
        # Extract input fields
        input_pattern = re.compile(r'<input[^>]*>', re.DOTALL)
        textarea_pattern = re.compile(r'<textarea[^>]*>(.*?)</textarea>', re.DOTALL)
        
        # Attribute patterns
        name_pattern = re.compile(r'name=["\'](.*?)["\']')
        type_pattern = re.compile(r'type=["\'](.*?)["\']')
        id_pattern = re.compile(r'id=["\'](.*?)["\']')
        
        inputs = []
        
        # Process forms first
        for form in forms:
            form_inputs = input_pattern.findall(form)
            form_textareas = textarea_pattern.findall(form)
            
            for input_tag in form_inputs:
                input_info = {"element": "input", "in_form": True}
                
                # Extract attributes
                name_match = name_pattern.search(input_tag)
                if name_match:
                    input_info["name"] = name_match.group(1)
                
                type_match = type_pattern.search(input_tag)
                if type_match:
                    input_info["type"] = type_match.group(1)
                else:
                    input_info["type"] = "text"  # Default type
                
                id_match = id_pattern.search(input_tag)
                if id_match:
                    input_info["id"] = id_match.group(1)
                
                inputs.append(input_info)
            
            for textarea in form_textareas:
                textarea_info = {"element": "textarea", "in_form": True}
                inputs.append(textarea_info)
        
        # Also look for inputs outside forms
        all_inputs = input_pattern.findall(content)
        for input_tag in all_inputs:
            if input_tag not in ''.join(forms):  # Skip inputs we already processed
                input_info = {"element": "input", "in_form": False}
                
                # Extract attributes
                name_match = name_pattern.search(input_tag)
                if name_match:
                    input_info["name"] = name_match.group(1)
                
                type_match = type_pattern.search(input_tag)
                if type_match:
                    input_info["type"] = type_match.group(1)
                else:
                    input_info["type"] = "text"  # Default type
                
                id_match = id_pattern.search(input_tag)
                if id_match:
                    input_info["id"] = id_match.group(1)
                
                inputs.append(input_info)
        
        return inputs
        
    except Exception as e:
        logger.error(f"Error identifying input fields from {url}: {str(e)}")
        return []

def crawl_website(base_url: str, max_depth: int = 2, max_pages: int = 10, 
                stay_on_domain: bool = True, respect_robots: bool = True) -> Dict[str, Any]:
    """
    Crawl a website to specified depth and extract content from multiple pages.
    
    Args:
        base_url (str): The base URL to start crawling from
        max_depth (int): Maximum crawl depth
        max_pages (int): Maximum number of pages to crawl
        stay_on_domain (bool): Whether to stay on the same domain
        respect_robots (bool): Whether to respect robots.txt
        
    Returns:
        Dict[str, Any]: Crawled pages with their content and metadata
    """
    # Initialize the crawl
    to_visit = [(base_url, 0)]  # (url, depth)
    visited = set()
    results = {}
    base_domain = urlparse(base_url).netloc
    
    page_count = 0
    
    logger.info(f"Starting crawl of {base_url} with max depth {max_depth} and max pages {max_pages}")
    
    while to_visit and page_count < max_pages:
        # Get the next URL to visit
        current_url, depth = to_visit.pop(0)
        
        # Skip if already visited or too deep
        if current_url in visited or depth > max_depth:
            continue
        
        # Mark as visited
        visited.add(current_url)
        
        try:
            logger.info(f"Crawling page {page_count+1}/{max_pages}: {current_url}")
            
            # Get the page content
            response = requests.get(current_url, timeout=10)
            if response.status_code != 200:
                logger.warning(f"Failed to fetch {current_url}, status code: {response.status_code}")
                continue
                
            # Extract the text content
            text_content = trafilatura.extract(response.text) or "No text extracted"
            
            # Parse the HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Get CSS stylesheets
            stylesheets = []
            for link in soup.find_all('link', rel='stylesheet', href=True):
                href = link['href']
                try:
                    # Make the URL absolute if it's relative
                    if href.startswith('/'):
                        css_url = f"{base_url.rstrip('/')}{href}"
                    elif not href.startswith('http'):
                        css_url = f"{base_url.rstrip('/')}/{href.lstrip('/')}"
                    else:
                        css_url = href
                        
                    # Fetch the CSS
                    css_response = requests.get(css_url, timeout=5)
                    if css_response.status_code == 200:
                        stylesheets.append({
                            "url": css_url,
                            "content": css_response.text
                        })
                except Exception as css_error:
                    logger.warning(f"Error fetching CSS {href}: {str(css_error)}")
                    continue
            
            # Get inline CSS
            inline_css = []
            for style in soup.find_all('style'):
                inline_css.append(style.string or "")
                
            # Get JavaScript files
            scripts = []
            for script in soup.find_all('script', src=True):
                src = script['src']
                try:
                    # Make the URL absolute if it's relative
                    if src.startswith('/'):
                        js_url = f"{base_url.rstrip('/')}{src}"
                    elif not src.startswith('http'):
                        js_url = f"{base_url.rstrip('/')}/{src.lstrip('/')}"
                    else:
                        js_url = src
                        
                    # Fetch the JavaScript
                    js_response = requests.get(js_url, timeout=5)
                    if js_response.status_code == 200:
                        scripts.append({
                            "url": js_url,
                            "content": js_response.text
                        })
                except Exception as js_error:
                    logger.warning(f"Error fetching JavaScript {src}: {str(js_error)}")
                    continue
            
            # Store the results
            results[current_url] = {
                "html": response.text,
                "text": text_content,
                "depth": depth,
                "status_code": response.status_code,
                "content_type": response.headers.get('Content-Type', ''),
                "stylesheets": stylesheets,
                "inline_css": inline_css,
                "scripts": scripts,
                "title": soup.title.string if soup.title else "No title"
            }
            
            page_count += 1
            logger.info(f"Successfully crawled page {page_count}/{max_pages}: {current_url}")
            
            # Stop if we've reached the maximum number of pages
            if page_count >= max_pages:
                logger.info(f"Reached maximum pages ({max_pages}), stopping crawl")
                break
                
            # If we're not at max depth, find more links
            if depth < max_depth:
                # Extract links
                links_found = 0
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    # Skip empty links, javascript, or anchors
                    if not href or href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                        continue
                        
                    next_url = urljoin(current_url, href)
                    
                    # Check if we should visit this URL
                    next_domain = urlparse(next_url).netloc
                    if next_url not in visited and next_url not in [u for u, _ in to_visit]:
                        if not stay_on_domain or next_domain == base_domain:
                            to_visit.append((next_url, depth + 1))
                            links_found += 1
                
                logger.info(f"Found {links_found} new links to crawl from {current_url}")
            
            # Be nice to the server
            time.sleep(0.5)
            
        except Exception as e:
            logger.error(f"Error crawling {current_url}: {str(e)}")
            # Just skip this URL on error
            continue
    
    logger.info(f"Crawl completed: Visited {len(visited)} URLs, extracted content from {len(results)} pages")
    return results


def analyze_attack_surface(url: str) -> Dict[str, Any]:
    """
    Perform a comprehensive analysis of a website's attack surface.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        Dict[str, Any]: Analysis of the attack surface
    """
    try:
        result = {
            "base_url": url,
            "discovered_urls": [],
            "input_fields": [],
            "potential_vectors": [],
            "technologies": []
        }
        
        # Extract URLs from the main page
        result["discovered_urls"] = extract_urls(url)
        
        # Identify input fields on the main page
        result["input_fields"] = identify_input_fields(url)
        
        # Create potential attack vectors based on input fields
        for input_field in result["input_fields"]:
            if input_field.get("type") in ["text", "search", "url", "email", "password"]:
                vector = {
                    "type": "input_field",
                    "subtype": input_field.get("type", "unknown"),
                    "name": input_field.get("name", "unknown"),
                    "potential_attacks": []
                }
                
                # Suggest potential attacks based on input type
                if input_field.get("type") == "text":
                    vector["potential_attacks"].extend(["XSS", "SQL Injection", "Command Injection"])
                elif input_field.get("type") == "search":
                    vector["potential_attacks"].extend(["XSS", "SQL Injection"])
                elif input_field.get("type") == "url":
                    vector["potential_attacks"].extend(["Open Redirect", "SSRF"])
                elif input_field.get("type") == "password":
                    vector["potential_attacks"].extend(["Brute Force", "Credential Stuffing"])
                
                result["potential_vectors"].append(vector)
        
        # Try to identify technologies
        try:
            headers = requests.head(url, timeout=5).headers
            
            # Check for server header
            if "Server" in headers:
                result["technologies"].append({"type": "server", "name": headers["Server"]})
            
            # Check for common technology headers
            if "X-Powered-By" in headers:
                result["technologies"].append({"type": "framework", "name": headers["X-Powered-By"]})
                
            # Check for common security headers
            security_headers = {
                "Strict-Transport-Security": False,
                "Content-Security-Policy": False,
                "X-Content-Type-Options": False,
                "X-Frame-Options": False,
                "X-XSS-Protection": False
            }
            
            for header in security_headers:
                if header in headers:
                    security_headers[header] = True
            
            result["security_headers"] = security_headers
            
        except Exception as e:
            logger.error(f"Error analyzing headers for {url}: {str(e)}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error analyzing attack surface for {url}: {str(e)}")
        return {
            "base_url": url,
            "error": str(e)
        }

def extract_sensitive_data(content: str) -> Dict[str, List[str]]:
    """
    Extract potentially sensitive data from content.
    
    Args:
        content (str): The HTML or text content to analyze
        
    Returns:
        Dict[str, List[str]]: Dictionary of found sensitive data
    """
    sensitive_data = {
        "emails": [],
        "phone_numbers": [],
        "api_keys": [],
        "potential_secrets": [],
        "social_security_numbers": [],
        "comments": []
    }
    
    # Extract emails
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    sensitive_data["emails"] = list(set(re.findall(email_pattern, content)))
    
    # Extract phone numbers (basic patterns)
    phone_patterns = [
        r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',         # 123-456-7890
        r'\b\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}\b',     # (123) 456-7890
        r'\b\+\d{1,3}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'  # +1 123-456-7890
    ]
    phones = []
    for pattern in phone_patterns:
        phones.extend(re.findall(pattern, content))
    sensitive_data["phone_numbers"] = list(set(phones))
    
    # Extract potential API keys
    api_key_patterns = [
        r'\b[A-Za-z0-9_-]{20,40}\b',  # General API key pattern
        r'\bsk_live_[A-Za-z0-9]{24,}\b',  # Stripe live key
        r'\bAIza[0-9A-Za-z_-]{35}\b'  # Google API key
    ]
    api_keys = []
    for pattern in api_key_patterns:
        api_keys.extend(re.findall(pattern, content))
    sensitive_data["api_keys"] = list(set(api_keys))
    
    # Extract potential secrets from variables
    secret_variable_pattern = r'\b(?:api_?key|api_?secret|token|password|secret|credential)[\'"\s:=]+([\'"][A-Za-z0-9_\-\.]{8,}[\'"])'
    potential_secrets = re.findall(secret_variable_pattern, content, re.IGNORECASE)
    # Clean up quotes
    sensitive_data["potential_secrets"] = [s.strip('\'"') for s in potential_secrets]
    
    # Extract HTML comments if it's HTML content
    if '<!--' in content:
        comment_pattern = r'<!--(.*?)-->'
        comments = re.findall(comment_pattern, content, re.DOTALL)
        sensitive_data["comments"] = [comment.strip() for comment in comments]
    
    return sensitive_data

def detect_technologies(content: str, headers: Dict[str, str] = None) -> List[Dict[str, str]]:
    """
    Detect technologies used by the website.
    
    Args:
        content (str): HTML content
        headers (Dict[str, str]): Response headers
        
    Returns:
        List[Dict[str, str]]: Detected technologies
    """
    technologies = []
    
    # Check for common CMS and frameworks
    cms_patterns = {
        "WordPress": r'wp-content|wp-includes|wordpress',
        "Drupal": r'drupal|Drupal\.|drupal\.js',
        "Joomla": r'joomla|Joomla!',
        "Magento": r'Magento|Mage\.Cookies',
        "Shopify": r'shopify|Shopify\.theme',
        "Wix": r'wix\.com|X-Wix-',
        "React": r'react|React\.|reactjs',
        "Angular": r'ng-|angular|Angular\.',
        "Vue.js": r'vue\.|Vue\.|vuejs',
        "jQuery": r'jquery|jQuery|jquery\.js',
        "Bootstrap": r'bootstrap|Bootstrap\.',
        "PHP": r'\.php|PHP|php\.js',
        "ASP.NET": r'ASP\.NET|\.aspx|__VIEWSTATE',
        "Node.js": r'node|nodejs|Express'
    }
    
    for tech, pattern in cms_patterns.items():
        if re.search(pattern, content, re.IGNORECASE):
            technologies.append({
                "name": tech,
                "confidence": "high",
                "version": "Unknown"  # Version detection would require more complex analysis
            })
    
    # Check headers for server technology
    if headers:
        if "Server" in headers:
            technologies.append({
                "name": headers["Server"],
                "confidence": "high",
                "type": "server"
            })
        
        if "X-Powered-By" in headers:
            technologies.append({
                "name": headers["X-Powered-By"],
                "confidence": "high",
                "type": "framework"
            })
    
    return technologies

def scan_for_vulnerabilities(url: str) -> Dict[str, Any]:
    """
    Scan for common vulnerabilities without performing actual exploitation.
    This is a passive scan that looks for indicators of potential vulnerabilities.
    
    Args:
        url (str): The URL to scan
        
    Returns:
        Dict[str, Any]: Detected potential vulnerabilities
    """
    vulnerabilities = {
        "xss_vectors": [],
        "sqli_vectors": [],
        "open_redirects": [],
        "information_disclosure": [],
        "insecure_configs": [],
        "csrf_risks": []
    }
    
    try:
        # Get the page content and inputs
        response = requests.get(url, timeout=10)
        content = response.text
        
        # Check for XSS vectors (input fields without proper validation)
        inputs = identify_input_fields(url)
        for input_field in inputs:
            # Check if it's a text type input that might be vulnerable to XSS
            input_type = input_field.get("type", "").lower()
            if input_type in ["text", "search", "url", "textarea", ""]:
                vulnerabilities["xss_vectors"].append({
                    "field": input_field.get("name", "unnamed"),
                    "type": input_type,
                    "form_action": input_field.get("form_action", ""),
                    "recommendation": "Implement output encoding and Content-Security-Policy"
                })
            
            # Check for potential SQL injection points
            if input_field.get("name", "").lower() in ["id", "userid", "user_id", "itemid", "item_id", "query", "search"]:
                vulnerabilities["sqli_vectors"].append({
                    "field": input_field.get("name", "unnamed"),
                    "form_action": input_field.get("form_action", ""),
                    "recommendation": "Use parameterized queries or ORM"
                })
            
            # Check for open redirect risks
            if input_field.get("name", "").lower() in ["redirect", "url", "return", "return_to", "redirect_to", "redirect_uri", "next"]:
                vulnerabilities["open_redirects"].append({
                    "field": input_field.get("name", "unnamed"),
                    "form_action": input_field.get("form_action", ""),
                    "recommendation": "Implement a whitelist of allowed redirect destinations"
                })
        
        # Check for CSRF risks (forms without anti-CSRF tokens)
        soup = BeautifulSoup(content, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            csrf_tokens = form.find_all('input', {'name': re.compile('csrf|token|nonce', re.IGNORECASE)})
            if not csrf_tokens:
                vulnerabilities["csrf_risks"].append({
                    "form_action": form.get('action', 'Unknown'),
                    "form_method": form.get('method', 'GET'),
                    "recommendation": "Implement anti-CSRF tokens"
                })
        
        # Check for information disclosure
        if re.search(r'(error|exception|stack trace|debug|warning):\s', content, re.IGNORECASE):
            vulnerabilities["information_disclosure"].append({
                "type": "Error messages",
                "recommendation": "Disable detailed error messages in production"
            })
        
        # Check for version disclosure
        version_patterns = [
            r'(jQuery v[0-9.]+)',
            r'(Bootstrap v[0-9.]+)',
            r'(WordPress [0-9.]+)',
            r'(PHP/[0-9.]+)',
            r'(Apache/[0-9.]+)'
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                vulnerabilities["information_disclosure"].append({
                    "type": "Version disclosure",
                    "version": match,
                    "recommendation": "Remove version information from public-facing pages"
                })
        
        return vulnerabilities
    except Exception as e:
        logger.error(f"Error scanning for vulnerabilities: {str(e)}")
        return {"error": f"Error scanning for vulnerabilities: {str(e)}"}