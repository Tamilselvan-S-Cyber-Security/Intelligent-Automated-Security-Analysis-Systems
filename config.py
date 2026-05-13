"""
Configuration settings for the Intelligent Automated Security Analysis System
Developed by Security Team - SKP Engineering College, CSE 4th Year
"""

# Intelligent Security Analysis System Configuration

# Display Settings
SHOW_ATTACK_SIMULATION_INFO = False  # Set to False to hide the attack simulation info box
SHOW_EDUCATIONAL_DISCLAIMERS = True  # Set to False to hide all educational disclaimers
INFO_BOX_STYLE = "hidden"  # Options: "always_visible", "collapsible", "hidden"

# Security Headers Configuration
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:; frame-ancestors 'none';",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()'
}

# Application Settings
DEBUG_MODE = True
LOG_LEVEL = "INFO"
MAX_SCAN_TIMEOUT = 300  # seconds
DEFAULT_TIMEOUT = 30    # seconds

# API Configuration
API_RATE_LIMIT = 100  # requests per minute
API_TIMEOUT = 30      # seconds

# Database Configuration (if applicable)
DATABASE_URL = "sqlite:///security_analyzer.db"

# Logging Configuration
LOG_FILE = "logs/security_analyzer.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Scan Configuration
SCAN_OPTIONS = {
    'xss': True,
    'sqli': True,
    'ports': True,
    'paths': True,
    'misconfig': True,
    'xxe': True,
    'ssrf': True,
    'rce': True,
    'idor': True,
    'csrf': True
}

# User Interface Settings
UI_THEME = "dark"  # Options: "light", "dark", "auto"
SHOW_ADVANCED_OPTIONS = False
ENABLE_REAL_TIME_SCANNING = True

# Default User-Agent string
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Maximum number of threads to use for scanning
MAX_THREADS = 10

# Default output file name
DEFAULT_OUTPUT_FILE = "security_analysis_report.txt"

# User preferences (can be modified by users)
PREFERENCES = {
    'verbose_output': False,
    'show_progress': True,
    'save_reports': True
}

# Scanner modules to enable by default
ENABLED_MODULES = {
    'xss_scanner': True,
    'sqli_scanner': True,
    'port_scanner': True,
    'path_scanner': True
}
