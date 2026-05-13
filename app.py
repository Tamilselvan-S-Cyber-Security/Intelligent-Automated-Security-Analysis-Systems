import os
import logging
from import os 
import secrets
import string
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_restful import Api, Resource

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SecurityAnalyzer')

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "cyberwolf-dev-key")

# Secure cookie configuration
# Note: SESSION_COOKIE_SECURE should be True in production (HTTPS only)
# Set to False in development if using HTTP
is_production = os.environ.get('FLASK_ENV') == 'production'
app.config.update(
    SESSION_COOKIE_SECURE=is_production,  # Only send cookie over HTTPS in production
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access to session cookie
    SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
    PERMANENT_SESSION_LIFETIME=1800,  # Session timeout (30 minutes)
)

api = Api(app)

# Simple API Key Management
class ApiKeyManager:
    """Simple file-based API key manager"""
    
    def __init__(self, storage_file="api_keys.json"):
        self.storage_file = storage_file
        self.keys = self._load_keys()
    
    def _load_keys(self):
        """Load API keys from storage file"""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logging.error(f"Error loading API keys: {str(e)}")
                return {}
        return {}
    
    def _save_keys(self):
        """Save API keys to storage file"""
        try:
            with open(self.storage_file, 'w') as f:
                json.dump(self.keys, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving API keys: {str(e)}")
    
    def generate_key(self, name):
        """Generate a new API key"""
        alphabet = string.ascii_letters + string.digits
        key = 'cwkey_' + ''.join(secrets.choice(alphabet) for _ in range(32))
        
        key_data = {
            'key': key,
            'name': name,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'last_used_at': None,
            'usage_count': 0,
            'is_active': True
        }
        
        self.keys[key] = key_data
        self._save_keys()
        return key_data
    
    def validate_key(self, key):
        """Validate an API key and update usage information"""
        if key in self.keys and self.keys[key]['is_active']:
            self.keys[key]['last_used_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.keys[key]['usage_count'] += 1
            self._save_keys()
            return True
        return False
    
    def get_all_keys(self):
        """Get all API keys"""
        return [{'key': key, **data} for key, data in self.keys.items()]
    
    def revoke_key(self, key):
        """Revoke an API key"""
        if key in self.keys:
            self.keys[key]['is_active'] = False
            self._save_keys()
            return True
        return False

# Initialize API Key Manager
api_key_manager = ApiKeyManager()

# Import scanner modules
from modules.scanner import VulnerabilityScanner
from utils.validator import validate_url
from utils.reporter import generate_report
from config import DEFAULT_TIMEOUT

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        url = request.form.get('url')
        scan_type = request.form.get('scan_type', 'basic')
        api_key = request.form.get('api_key', None) if scan_type == 'api' else None
        
        # Get timeout value (default to DEFAULT_TIMEOUT if invalid)
        try:
            timeout = int(request.form.get('timeout', DEFAULT_TIMEOUT))
            if timeout < 5 or timeout > 60:
                timeout = DEFAULT_TIMEOUT
                flash('Invalid timeout value. Using default timeout.', 'warning')
        except ValueError:
            timeout = DEFAULT_TIMEOUT
            flash('Invalid timeout format. Using default timeout.', 'warning')
        
        # Get attack options
        attack_options = {
            'xss': 'attack_xss' in request.form,
            'sqli': 'attack_sqli' in request.form,
            'ports': 'attack_ports' in request.form,
            'paths': 'attack_paths' in request.form
        }
        
        # Validate URL
        if not validate_url(url):
            flash('Invalid URL format. Please enter a valid URL.', 'danger')
            return redirect(url_for('scan'))
        
        # Validate API key if API scan is selected
        if scan_type == 'api' and api_key:
            if not api_key_manager.validate_key(api_key):
                flash('Invalid API key. Please provide a valid API key or generate a new one.', 'danger')
                return redirect(url_for('scan'))
        
        # Ensure at least one scan type is selected
        if not any(attack_options.values()):
            flash('Please select at least one attack type to perform.', 'warning')
            return redirect(url_for('scan'))
        
        try:
            # Run the scan
            scanner = VulnerabilityScanner(
                url=url,
                timeout=timeout,
                api_key=api_key,
                verbose=True
            )
            
            # Run selected scans
            scan_results = scanner.run_all_scans(attack_options)
            
            # Store scan information in session for report page
            session['scan_results'] = scan_results
            session['target_url'] = url
            session['scan_info'] = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'scan_type': scan_type,
                'timeout': timeout,
                'attack_options': attack_options
            }
            
            # Redirect to results page
            return redirect(url_for('results'))
            
        except Exception as e:
            app.logger.error(f"Error during scan: {str(e)}")
            flash(f'Error during scan: {str(e)}', 'danger')
            return redirect(url_for('scan'))
    
    return render_template('scan.html')

@app.route('/results')
def results():
    # Get results from session
    results = session.get('scan_results')
    target_url = session.get('target_url')
    
    if not results or not target_url:
        flash('No scan results available. Please run a scan first.', 'warning')
        return redirect(url_for('scan'))
    
    # Get current time
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    return render_template('results.html', results=results, target_url=target_url, current_time=current_time)

@app.route('/download_report')
def download_report():
    # Get results from session
    results = session.get('scan_results')
    target_url = session.get('target_url')
    
    if not results or not target_url:
        flash('No scan results available. Please run a scan first.', 'warning')
        return redirect(url_for('scan'))
    
    # Generate plain text report (without color codes)
    report_text = generate_text_report(target_url, results)
    
    response = app.response_class(
        response=report_text,
        status=200,
        mimetype='text/plain'
    )
    response.headers["Content-Disposition"] = "attachment; filename=cyberwolf_report.txt"
    
    return response

@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/roadmap')
def roadmap():
    """Future roadmap page"""
    return render_template('roadmap.html')

@app.route('/sample')
def sample_website():
    """Serve the sample API documentation website"""
    return render_template('sample_website.html')

@app.route('/api-docs')
def api_docs():
    """Serve the API documentation page"""
    return render_template('api_docs.html')

# API Key Management Routes
@app.route('/api-keys', methods=['GET', 'POST'])
def api_keys():
    """View and generate API keys"""
    if request.method == 'POST':
        key_name = request.form.get('key_name', '').strip()
        if not key_name:
            flash('Please provide a name for the API key', 'warning')
        else:
            key_data = api_key_manager.generate_key(key_name)
            flash(f'API key generated successfully: {key_data["key"]}', 'success')
        
    keys = api_key_manager.get_all_keys()
    return render_template('api_keys.html', keys=keys)

@app.route('/api-keys/revoke/<key>', methods=['POST'])
def revoke_api_key(key):
    """Revoke an API key"""
    if api_key_manager.revoke_key(key):
        flash('API key revoked successfully', 'success')
    else:
        flash('Failed to revoke API key', 'danger')
    return redirect(url_for('api_keys'))

@app.route('/api/validate-key', methods=['POST'])
def validate_api_key():
    """API endpoint to validate an API key"""
    key = request.json.get('key', '')
    is_valid = api_key_manager.validate_key(key)
    return jsonify({'valid': is_valid})

@app.route('/api/keys', methods=['GET', 'POST'])
def api_keys_endpoint():
    """API endpoint for managing API keys"""
    # Require admin API key for this endpoint
    admin_key = request.headers.get('X-Admin-API-Key')
    if not admin_key or admin_key != os.environ.get('ADMIN_API_KEY', 'admin-key-dev'):
        return jsonify({'error': 'Unauthorized access'}), 401
    
    if request.method == 'GET':
        # List all API keys
        keys = api_key_manager.get_all_keys()
        return jsonify({'keys': keys})
    
    elif request.method == 'POST':
        # Generate new API key
        data = request.json
        key_name = data.get('name')
        
        if not key_name:
            return jsonify({'error': 'Key name is required'}), 400
        
        key_data = api_key_manager.generate_key(key_name)
        return jsonify({'key': key_data}), 201

@app.route('/api/keys/<key>', methods=['DELETE'])
def api_key_management(key):
    """API endpoint for individual key operations"""
    # Require admin API key for this endpoint
    admin_key = request.headers.get('X-Admin-API-Key')
    if not admin_key or admin_key != os.environ.get('ADMIN_API_KEY', 'admin-key-dev'):
        return jsonify({'error': 'Unauthorized access'}), 401
    
    if request.method == 'DELETE':
        # Revoke API key
        if api_key_manager.revoke_key(key):
            return jsonify({'success': True}), 200
        else:
            return jsonify({'error': 'Key not found'}), 404

# Helper function for generating plain text report (without color codes)
def generate_text_report(target_url, results):
    # Similar to utils.reporter.generate_report but without color codes
    from datetime import datetime
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Report header
    report = [
        "=" * 80,
        "Intelligent Automated Security Analysis System - Scan Report",
        "Developed by Security Team - SKP Engineering College, CSE 4th Year",
        f"Generated: {now}",
        f"Target: {target_url}",
        "=" * 80,
    ]
    
    # Executive summary
    total_vulns = sum(results['summary'].values())
    risk_level = results['summary'].get('risk_level', 'Unknown')
    
    report.append("\nEXECUTIVE SUMMARY:")
    report.append(f"Total vulnerabilities found: {total_vulns}")
    report.append(f"Overall risk level: {risk_level}")
    report.append("-" * 80)
    
    # XSS Vulnerabilities
    if results.get('xss'):
        report.append("\nCROSS-SITE SCRIPTING (XSS) VULNERABILITIES:")
        report.append(f"Found: {len(results['xss'])}")
        
        for i, vuln in enumerate(results['xss'], 1):
            report.append(f"\n  {i}. Location: {vuln.get('location', 'Unknown')}")
            report.append(f"     Method: {vuln.get('method', 'GET')}")
            report.append(f"     Parameter: {vuln.get('param', 'N/A')}")
            report.append(f"     Payload: {vuln.get('payload', 'N/A')}")
            report.append(f"     URL: {vuln.get('url', 'N/A')}")
    else:
        report.append("\nNO CROSS-SITE SCRIPTING (XSS) VULNERABILITIES FOUND")
    
    # SQL Injection Vulnerabilities
    if results.get('sqli'):
        report.append("\nSQL INJECTION VULNERABILITIES:")
        report.append(f"Found: {len(results['sqli'])}")
        
        for i, vuln in enumerate(results['sqli'], 1):
            report.append(f"\n  {i}. Location: {vuln.get('location', 'Unknown')}")
            report.append(f"     Method: {vuln.get('method', 'GET')}")
            report.append(f"     Parameter: {vuln.get('param', 'N/A')}")
            report.append(f"     Payload: {vuln.get('payload', 'N/A')}")
            report.append(f"     Type: {vuln.get('error_type', 'Unknown')}")
            report.append(f"     URL: {vuln.get('url', 'N/A')}")
    else:
        report.append("\nNO SQL INJECTION VULNERABILITIES FOUND")
    
    # Port Scan Results
    if results.get('ports'):
        report.append("\nOPEN PORTS AND SERVICES:")
        report.append(f"Found: {len(results['ports'])}")
        
        for i, port in enumerate(results['ports'], 1):
            report.append(f"\n  {i}. Port: {port.get('port')}/{port.get('protocol', 'tcp')}")
            report.append(f"     Service: {port.get('service', 'Unknown')}")
            report.append(f"     State: {port.get('state', 'open')}")
    else:
        report.append("\nNO OPEN PORTS DETECTED")
    
    # Path Scan Results
    if results.get('paths'):
        report.append("\nVULNERABLE PATHS AND DIRECTORIES:")
        report.append(f"Found: {len(results['paths'])}")
        
        # Group by risk level
        high_risk = [p for p in results['paths'] if p.get('risk_level') == 'High']
        medium_risk = [p for p in results['paths'] if p.get('risk_level') == 'Medium']
        
        if high_risk:
            report.append("\n  HIGH RISK PATHS:")
            for i, path in enumerate(high_risk, 1):
                report.append(f"  {i}. {path.get('path')}")
                report.append(f"     URL: {path.get('full_url')}")
                report.append(f"     Status: {path.get('status')} (Code: {path.get('status_code')})")
        
        if medium_risk:
            report.append("\n  MEDIUM RISK PATHS:")
            for i, path in enumerate(medium_risk, 1):
                report.append(f"  {i}. {path.get('path')}")
                report.append(f"     URL: {path.get('full_url')}")
                report.append(f"     Status: {path.get('status')} (Code: {path.get('status_code')})")
    else:
        report.append("\nNO VULNERABLE PATHS DETECTED")
    
    # Remediation recommendations
    report.append("\nREMEDIATION RECOMMENDATIONS:")
    
    if results.get('xss'):
        report.append("\nFor XSS vulnerabilities:")
        report.append("  - Implement proper input validation and sanitization")
        report.append("  - Use Content-Security-Policy headers")
        report.append("  - Apply output encoding when rendering user input")
        report.append("  - Consider using frameworks with built-in XSS protection")
    
    if results.get('sqli'):
        report.append("\nFor SQL Injection vulnerabilities:")
        report.append("  - Use parameterized queries or prepared statements")
        report.append("  - Implement proper input validation and sanitization")
        report.append("  - Apply the principle of least privilege for database users")
        report.append("  - Consider using ORM frameworks")
    
    if results.get('ports'):
        report.append("\nFor open ports:")
        report.append("  - Close unnecessary ports and services")
        report.append("  - Implement proper firewall rules")
        report.append("  - Keep services updated to the latest secure versions")
        report.append("  - Use network segmentation where possible")
    
    if results.get('paths'):
        report.append("\nFor vulnerable paths:")
        report.append("  - Remove or secure sensitive files from web-accessible directories")
        report.append("  - Implement proper access controls and authentication")
        report.append("  - Configure web server to deny access to sensitive directories")
        report.append("  - Use .htaccess or web.config files to restrict access")
    
    # Report footer
    report.append("\n" + "=" * 80)
    report.append("End of Report - Developed by Security Team - SKP Engineering College, CSE 4th Year")
    report.append("=" * 80 + "\n")
    
    return "\n".join(report)

# Add custom error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500

@app.errorhandler(429)
def too_many_requests(error):
    return render_template('errors/429.html'), 429

# Add rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.storage import MemoryStorage  # Import for dev, use Redis in production

# Configure limiter with explicit storage
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage=MemoryStorage()  # Explicitly set storage to remove warning
)

# Apply rate limiting to scan endpoint
@limiter.limit("5 per minute")
@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        url = request.form.get('url')
        scan_type = request.form.get('scan_type', 'basic')
        api_key = request.form.get('api_key', None) if scan_type == 'api' else None
        
        # Get timeout value (default to DEFAULT_TIMEOUT if invalid)
        try:
            timeout = int(request.form.get('timeout', DEFAULT_TIMEOUT))
            if timeout < 5 or timeout > 60:
                timeout = DEFAULT_TIMEOUT
                flash('Invalid timeout value. Using default timeout.', 'warning')
        except ValueError:
            timeout = DEFAULT_TIMEOUT
            flash('Invalid timeout format. Using default timeout.', 'warning')
        
        # Get attack options
        attack_options = {
            'xss': 'attack_xss' in request.form,
            'sqli': 'attack_sqli' in request.form,
            'ports': 'attack_ports' in request.form,
            'paths': 'attack_paths' in request.form
        }
        
        # Validate URL
        if not validate_url(url):
            flash('Invalid URL format. Please enter a valid URL.', 'danger')
            return redirect(url_for('scan'))
        
        # Validate API key if API scan is selected
        if scan_type == 'api' and api_key:
            if not api_key_manager.validate_key(api_key):
                flash('Invalid API key. Please provide a valid API key or generate a new one.', 'danger')
                return redirect(url_for('scan'))
        
        # Ensure at least one scan type is selected
        if not any(attack_options.values()):
            flash('Please select at least one attack type to perform.', 'warning')
            return redirect(url_for('scan'))
        
        try:
            # Run the scan
            scanner = VulnerabilityScanner(
                url=url,
                timeout=timeout,
                api_key=api_key,
                verbose=True
            )
            
            # Run selected scans
            scan_results = scanner.run_all_scans(attack_options)
            
            # Store scan information in session for report page
            session['scan_results'] = scan_results
            session['target_url'] = url
            session['scan_info'] = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'scan_type': scan_type,
                'timeout': timeout,
                'attack_options': attack_options
            }
            
            # Redirect to results page
            return redirect(url_for('results'))
            
        except Exception as e:
            app.logger.error(f"Error during scan: {str(e)}")
            flash(f'Error during scan: {str(e)}', 'danger')
            return redirect(url_for('scan'))
    
    return render_template('scan.html')

@app.route('/results')
def results():
    # Get results from session
    results = session.get('scan_results')
    target_url = session.get('target_url')
    
    if not results or not target_url:
        flash('No scan results available. Please run a scan first.', 'warning')
        return redirect(url_for('scan'))
    
    # Get current time
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    return render_template('results.html', results=results, target_url=target_url, current_time=current_time)

@app.route('/download_report')
def download_report():
    # Get results from session
    results = session.get('scan_results')
    target_url = session.get('target_url')
    
    if not results or not target_url:
        flash('No scan results available. Please run a scan first.', 'warning')
        return redirect(url_for('scan'))
    
    # Generate plain text report (without color codes)
    report_text = generate_text_report(target_url, results)
    
    response = app.response_class(
        response=report_text,
        status=200,
        mimetype='text/plain'
    )
    response.headers["Content-Disposition"] = "attachment; filename=cyberwolf_report.txt"
    
    return response

@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/roadmap')
def roadmap():
    """Future roadmap page"""
    return render_template('roadmap.html')

@app.route('/sample')
def sample_website():
    """Serve the sample API documentation website"""
    return render_template('sample_website.html')

@app.route('/api-docs')
def api_docs():
    """Serve the API documentation page"""
    return render_template('api_docs.html')

# API Key Management Routes
@app.route('/api-keys', methods=['GET', 'POST'])
def api_keys():
    """View and generate API keys"""
    if request.method == 'POST':
        key_name = request.form.get('key_name', '').strip()
        if not key_name:
            flash('Please provide a name for the API key', 'warning')
        else:
            key_data = api_key_manager.generate_key(key_name)
            flash(f'API key generated successfully: {key_data["key"]}', 'success')
        
    keys = api_key_manager.get_all_keys()
    return render_template('api_keys.html', keys=keys)

@app.route('/api-keys/revoke/<key>', methods=['POST'])
def revoke_api_key(key):
    """Revoke an API key"""
    if api_key_manager.revoke_key(key):
        flash('API key revoked successfully', 'success')
    else:
        flash('Failed to revoke API key', 'danger')
    return redirect(url_for('api_keys'))

@app.route('/api/validate-key', methods=['POST'])
def validate_api_key():
    """API endpoint to validate an API key"""
    key = request.json.get('key', '')
    is_valid = api_key_manager.validate_key(key)
    return jsonify({'valid': is_valid})

@app.route('/api/keys', methods=['GET', 'POST'])
def api_keys_endpoint():
    """API endpoint for managing API keys"""
    # Require admin API key for this endpoint
    admin_key = request.headers.get('X-Admin-API-Key')
    if not admin_key or admin_key != os.environ.get('ADMIN_API_KEY', 'admin-key-dev'):
        return jsonify({'error': 'Unauthorized access'}), 401
    
    if request.method == 'GET':
        # List all API keys
        keys = api_key_manager.get_all_keys()
        return jsonify({'keys': keys})
    
    elif request.method == 'POST':
        # Generate new API key
        data = request.json
        key_name = data.get('name')
        
        if not key_name:
            return jsonify({'error': 'Key name is required'}), 400
        
        key_data = api_key_manager.generate_key(key_name)
        return jsonify({'key': key_data}), 201

@app.route('/api/keys/<key>', methods=['DELETE'])
def api_key_management(key):
    """API endpoint for individual key operations"""
    # Require admin API key for this endpoint
    admin_key = request.headers.get('X-Admin-API-Key')
    if not admin_key or admin_key != os.environ.get('ADMIN_API_KEY', 'admin-key-dev'):
        return jsonify({'error': 'Unauthorized access'}), 401
    
    if request.method == 'DELETE':
        # Revoke API key
        if api_key_manager.revoke_key(key):
            return jsonify({'success': True}), 200
        else:
            return jsonify({'error': 'Key not found'}), 404

# Helper function for generating plain text report (without color codes)
def generate_text_report(target_url, results):
    # Similar to utils.reporter.generate_report but without color codes
    from datetime import datetime
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Report header
    report = [
        "=" * 80,
        "Intelligent Automated Security Analysis System - Scan Report",
        "Developed by Security Team - SKP Engineering College, CSE 4th Year",
        f"Generated: {now}",
        f"Target: {target_url}",
        "=" * 80,
    ]
    
    # Executive summary
    total_vulns = sum(results['summary'].values())
    risk_level = results['summary'].get('risk_level', 'Unknown')
    
    report.append("\nEXECUTIVE SUMMARY:")
    report.append(f"Total vulnerabilities found: {total_vulns}")
    report.append(f"Overall risk level: {risk_level}")
    report.append("-" * 80)
    
    # XSS Vulnerabilities
    if results.get('xss'):
        report.append("\nCROSS-SITE SCRIPTING (XSS) VULNERABILITIES:")
        report.append(f"Found: {len(results['xss'])}")
        
        for i, vuln in enumerate(results['xss'], 1):
            report.append(f"\n  {i}. Location: {vuln.get('location', 'Unknown')}")
            report.append(f"     Method: {vuln.get('method', 'GET')}")
            report.append(f"     Parameter: {vuln.get('param', 'N/A')}")
            report.append(f"     Payload: {vuln.get('payload', 'N/A')}")
            report.append(f"     URL: {vuln.get('url', 'N/A')}")
    else:
        report.append("\nNO CROSS-SITE SCRIPTING (XSS) VULNERABILITIES FOUND")
    
    # SQL Injection Vulnerabilities
    if results.get('sqli'):
        report.append("\nSQL INJECTION VULNERABILITIES:")
        report.append(f"Found: {len(results['sqli'])}")
        
        for i, vuln in enumerate(results['sqli'], 1):
            report.append(f"\n  {i}. Location: {vuln.get('location', 'Unknown')}")
            report.append(f"     Method: {vuln.get('method', 'GET')}")
            report.append(f"     Parameter: {vuln.get('param', 'N/A')}")
            report.append(f"     Payload: {vuln.get('payload', 'N/A')}")
            report.append(f"     Type: {vuln.get('error_type', 'Unknown')}")
            report.append(f"     URL: {vuln.get('url', 'N/A')}")
    else:
        report.append("\nNO SQL INJECTION VULNERABILITIES FOUND")
    
    # Port Scan Results
    if results.get('ports'):
        report.append("\nOPEN PORTS AND SERVICES:")
        report.append(f"Found: {len(results['ports'])}")
        
        for i, port in enumerate(results['ports'], 1):
            report.append(f"\n  {i}. Port: {port.get('port')}/{port.get('protocol', 'tcp')}")
            report.append(f"     Service: {port.get('service', 'Unknown')}")
            report.append(f"     State: {port.get('state', 'open')}")
    else:
        report.append("\nNO OPEN PORTS DETECTED")
    
    # Path Scan Results
    if results.get('paths'):
        report.append("\nVULNERABLE PATHS AND DIRECTORIES:")
        report.append(f"Found: {len(results['paths'])}")
        
        # Group by risk level
        high_risk = [p for p in results['paths'] if p.get('risk_level') == 'High']
        medium_risk = [p for p in results['paths'] if p.get('risk_level') == 'Medium']
        
        if high_risk:
            report.append("\n  HIGH RISK PATHS:")
            for i, path in enumerate(high_risk, 1):
                report.append(f"  {i}. {path.get('path')}")
                report.append(f"     URL: {path.get('full_url')}")
                report.append(f"     Status: {path.get('status')} (Code: {path.get('status_code')})")
        
        if medium_risk:
            report.append("\n  MEDIUM RISK PATHS:")
            for i, path in enumerate(medium_risk, 1):
                report.append(f"  {i}. {path.get('path')}")
                report.append(f"     URL: {path.get('full_url')}")
                report.append(f"     Status: {path.get('status')} (Code: {path.get('status_code')})")
    else:
        report.append("\nNO VULNERABLE PATHS DETECTED")
    
    # Remediation recommendations
    report.append("\nREMEDIATION RECOMMENDATIONS:")
    
    if results.get('xss'):
        report.append("\nFor XSS vulnerabilities:")
        report.append("  - Implement proper input validation and sanitization")
        report.append("  - Use Content-Security-Policy headers")
        report.append("  - Apply output encoding when rendering user input")
        report.append("  - Consider using frameworks with built-in XSS protection")
    
    if results.get('sqli'):
        report.append("\nFor SQL Injection vulnerabilities:")
        report.append("  - Use parameterized queries or prepared statements")
        report.append("  - Implement proper input validation and sanitization")
        report.append("  - Apply the principle of least privilege for database users")
        report.append("  - Consider using ORM frameworks")
    
    if results.get('ports'):
        report.append("\nFor open ports:")
        report.append("  - Close unnecessary ports and services")
        report.append("  - Implement proper firewall rules")
        report.append("  - Keep services updated to the latest secure versions")
        report.append("  - Use network segmentation where possible")
    
    if results.get('paths'):
        report.append("\nFor vulnerable paths:")
        report.append("  - Remove or secure sensitive files from web-accessible directories")
        report.append("  - Implement proper access controls and authentication")
        report.append("  - Configure web server to deny access to sensitive directories")
        report.append("  - Use .htaccess or web.config files to restrict access")
    
    # Report footer
    report.append("\n" + "=" * 80)
    report.append("End of Report - Developed by Security Team - SKP Engineering College, CSE 4th Year")
    report.append("=" * 80 + "\n")
    
    return "\n".join(report)

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Configure file logging
    file_handler = logging.FileHandler('logs/app.log')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    app.logger.addHandler(file_handler)
    
    # Run the Flask app
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    )

# Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:; frame-ancestors 'none';"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()'
    return response

# Add health check endpoint
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

# Add metrics endpoint
@app.route('/metrics')
def metrics():
    if not request.headers.get('X-Admin-API-Key') == os.environ.get('ADMIN_API_KEY'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    return jsonify({
        'api_keys': len(api_key_manager.get_all_keys()),
        'active_sessions': len(session.keys()) if session else 0,
        'uptime': 'N/A',  # Implement uptime tracking
        'scan_count': session.get('total_scans', 0)
    })

# Add configuration validation
def validate_config():
    required_vars = [
        'SESSION_SECRET',
        'ADMIN_API_KEY',
        'MAX_SCAN_TIMEOUT',
        'DEFAULT_TIMEOUT'
    ]
    
    missing = [var for var in required_vars if not os.environ.get(var)]
    if missing:
        logger.warning(f"Missing environment variables: {', '.join(missing)}")
        return False
    return True

if __name__ == '__main__':
    # Validate configuration
    if not validate_config():
        logger.warning("Running with default configuration")
    
    # Create necessary directories
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Configure file logging
    file_handler = logging.FileHandler('logs/app.log')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    app.logger.addHandler(file_handler)
    
    # Run the Flask app
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    )

