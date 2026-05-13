"""
Input validation utilities
"""

import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger('CyberWolf.Validator')

def validate_url(url):
    """
    Validate URL format and accessibility
    
    Args:
        url (str): URL to validate
    
    Returns:
        bool: True if URL is valid, False otherwise
    """
    # Check if URL is empty
    if not url:
        logger.warning("Empty URL provided")
        return False
    
    # Add http:// prefix if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Check URL format
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            logger.warning(f"Invalid URL format: {url}")
            return False
        
        # Basic URL pattern check
        url_pattern = re.compile(
            r'^(https?:\/\/)?'  # http:// or https://
            r'([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+'  # domain
            r'(\.[a-zA-Z0-9-]+)*(:[0-9]+)?'  # port
            r'(\/[^\/\s]*)*$'  # path
        )
        
        if not url_pattern.match(url):
            logger.warning(f"URL doesn't match pattern: {url}")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error validating URL {url}: {str(e)}")
        return False
