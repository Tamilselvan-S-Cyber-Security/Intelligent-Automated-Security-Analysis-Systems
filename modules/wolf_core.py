"""
Core functionality for the CyberWolf Security Analyzer

This module contains the core functions and classes for the CyberWolf Security Analyzer,
including API key management, encryption, and security analysis utilities.
"""

import os
import base64
import secrets
import string
import hashlib
import concurrent.futures
from typing import Dict, Any, List, Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime

# Default API key for enhanced scanning
DEFAULT_API_KEY = 'AIzaSyABge7vHFTpvZykbQd_EDvoT35-eSvZp2s'

# Encryption key - in production, this should be stored securely
ENCRYPTION_KEY = b'AIzaSyABge7vHFTpvZykbQd_EDvoT35-eSvZp2s'  # This is just an example, use a proper key
cipher_suite = Fernet(base64.urlsafe_b64encode(ENCRYPTION_KEY.ljust(32)[:32]))

def encrypt_api_key(api_key: str) -> Optional[str]:
    """
    Encrypt the API key using Fernet encryption.
    
    Args:
        api_key (str): The API key to encrypt
        
    Returns:
        Optional[str]: The encrypted API key or None if encryption fails
    """
    if not api_key:
        return None
        
    try:
        encrypted_key = cipher_suite.encrypt(api_key.encode())
        return encrypted_key.decode()
    except Exception as e:
        print(f"Error encrypting API key: {str(e)}")
        return None

def decrypt_api_key(encrypted_key: str) -> Optional[str]:
    """
    Decrypt the API key using Fernet encryption.
    
    Args:
        encrypted_key (str): The encrypted API key
        
    Returns:
        Optional[str]: The decrypted API key or None if decryption fails
    """
    if not encrypted_key:
        return None
        
    try:
        decrypted_key = cipher_suite.decrypt(encrypted_key.encode())
        return decrypted_key.decode()
    except Exception as e:
        print(f"Error decrypting API key: {str(e)}")
        return None

def generate_key_method1() -> str:
    """Generate API key using method 1: Random characters with special symbols"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(32))

def generate_key_method2() -> str:
    """Generate API key using method 2: Base64 encoded random bytes"""
    return base64.urlsafe_b64encode(os.urandom(32)).decode()

def generate_key_method3() -> str:
    """Generate API key using method 3: SHA-256 hash of random data"""
    random_data = os.urandom(32)
    return hashlib.sha256(random_data).hexdigest()

def generate_key_method4() -> str:
    """Generate API key using method 4: PBKDF2 derived key"""
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(os.urandom(32))
    return base64.urlsafe_b64encode(key).decode()

def generate_api_key(method: str = "default") -> Tuple[Optional[str], Optional[str]]:
    """
    Generate a new API key using the specified method.
    
    Args:
        method (str): The method to use for key generation
        
    Returns:
        Tuple[Optional[str], Optional[str]]: The API key and encrypted key, or (None, None) if generation fails
    """
    try:
        if method == "default":
            api_key = DEFAULT_API_KEY
        elif method == "method1":
            api_key = generate_key_method1()
        elif method == "method2":
            api_key = generate_key_method2()
        elif method == "method3":
            api_key = generate_key_method3()
        elif method == "method4":
            api_key = generate_key_method4()
        else:
            print(f"Invalid key generation method: {method}")
            return None, None
            
        encrypted_key = encrypt_api_key(api_key)
        
        if not encrypted_key:
            return None, None
            
        return api_key, encrypted_key
    except Exception as e:
        print(f"Error generating API key: {str(e)}")
        return None, None

def calculate_security_score(results: List[Dict[str, Any]]) -> int:
    """
    Calculate a security score based on scan results
    
    Args:
        results (List[Dict[str, Any]]): List of scan results
        
    Returns:
        int: Security score from 0-100
    """
    total_issues = sum(len(r.get('issues', [])) for r in results)
    critical_issues = sum(1 for r in results for issue in r.get('issues', [])
                         if issue.get('priority') == 'Critical')
    
    return max(0, 100 - (critical_issues * 20) - (total_issues * 5))

def group_findings_by_category(results: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Group findings by category for better organization
    
    Args:
        results (List[Dict[str, Any]]): List of scan results
        
    Returns:
        Dict[str, List[Dict[str, Any]]]: Findings grouped by category
    """
    categories = {}
    for result in results:
        for issue in result.get('issues', []):
            category = issue.get('category', 'Other')
            if category not in categories:
                categories[category] = []
            categories[category].append(issue)
    
    return categories

def generate_report_summary(results: List[Dict[str, Any]]) -> str:
    """
    Generate a concise summary of the analysis
    
    Args:
        results (List[Dict[str, Any]]): List of scan results
        
    Returns:
        str: Summary text
    """
    total_issues = sum(len(r.get('issues', [])) for r in results)
    critical_issues = sum(1 for r in results for issue in r.get('issues', [])
                         if issue.get('priority') == 'Critical')
    
    return f"""
    Security Analysis Summary
    ------------------------
    Total Issues: {total_issues}
    Critical Issues: {critical_issues}
    Security Score: {calculate_security_score(results)}/100
    
    Key Findings:
    {chr(10).join(f"- {issue['title']} ({issue['priority']})" 
                  for r in results 
                  for issue in r.get('issues', []) 
                  if issue.get('priority') in ['Critical', 'High'])}
    """
