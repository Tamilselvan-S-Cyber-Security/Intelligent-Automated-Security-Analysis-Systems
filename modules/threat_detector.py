"""
Security Threat Detection Module

This module contains functions for detecting security threats in code and configurations.
"""

import streamlit as st
import concurrent.futures
from typing import Dict, Any, List

def handle_threat_detection(api_client, security_analyzer):
    """
    Handle the security threat detection workflow

    Args:
        api_client: The API client for making security analysis requests
        security_analyzer: The security analyzer module
    """
    st.subheader("🛡️ Security Threat Detection")

    st.markdown("<div class='glass-section-header'>Input Content for Analysis</div>", unsafe_allow_html=True)

    threat_input = st.text_area("Enter code, configuration, or text to analyze for security threats",
                                height=200,
                                placeholder="Paste code, configurations, or any text you want to analyze for security threats...")

    # Code examples
    st.markdown("<div class='helper-text'>Try with these example security scenarios:</div>", unsafe_allow_html=True)

    code_examples = {
        "SQL Injection": """def login(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()""",

        "XSS Vulnerability": """function displayComment(comment) {
    document.getElementById('comments').innerHTML += comment;
}""",

        "Hardcoded Credentials": """const apiKey = 'ak_live_1234567890abcdef';
const dbPassword = 'admin123';

function connectToService() {
    return new ServiceClient(apiKey, dbPassword);
}"""
    }

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("SQL Injection Example"):
            st.session_state['code_example'] = code_examples["SQL Injection"]
    with col2:
        if st.button("XSS Vulnerability Example"):
            st.session_state['code_example'] = code_examples["XSS Vulnerability"]
    with col3:
        if st.button("Hardcoded Credentials Example"):
            st.session_state['code_example'] = code_examples["Hardcoded Credentials"]

    # Apply the selected code example if in session state
    if 'code_example' in st.session_state:
        threat_input = st.session_state['code_example']

    col1, col2 = st.columns(2)
    with col1:
        input_type = st.selectbox("Select Input Type",
                                 ["Automatic Detection", "Source Code", "Config File", "Log Data", "Network Data"])

    with col2:
        language = st.selectbox("Programming Language (if applicable)",
                               ["Automatic Detection", "Python", "JavaScript", "PHP", "Java", "C/C++", "Go", "Ruby", "Other"])

    analyze_button = st.button("Detect Security Threats", type="primary")

    if analyze_button and threat_input:
        with st.spinner("🐺 Wolf API is analyzing for security threats..."):
            try:
                # Use concurrent.futures to parallelize threat analysis
                results = {}

                # Create a list to store the futures and their task names
                futures_with_names = []

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    # Split the analysis into multiple tasks and track the task names
                    futures_with_names.append(
                        ('syntax_analysis', executor.submit(security_analyzer.analyze_threats, api_client, threat_input, input_type, language, analysis_type='syntax'))
                    )
                    futures_with_names.append(
                        ('vulnerability_analysis', executor.submit(security_analyzer.analyze_threats, api_client, threat_input, input_type, language, analysis_type='vulnerability'))
                    )
                    futures_with_names.append(
                        ('security_analysis', executor.submit(security_analyzer.analyze_threats, api_client, threat_input, input_type, language, analysis_type='security'))
                    )

                    # Collect results as they complete
                    for task_name, future in futures_with_names:
                        try:
                            results[task_name] = future.result()
                        except Exception as e:
                            st.error(f"Error in {task_name}: {str(e)}")
                            results[task_name] = {
                                "summary": f"Error in {task_name} analysis",
                                "threats": [],
                                "recommendations": []
                            }

                # Merge results from different analysis types
                result = security_analyzer.merge_threat_results(results.values())

                # Display results
                display_threat_results(result)

            except Exception as e:
                st.error(f"An error occurred during threat analysis: {str(e)}")

    st.markdown("""
    <div class='info-box'>
        <h3>About Security Threat Detection</h3>
        <p>This tool analyzes code, configurations, and other text data to identify potential security threats and vulnerabilities.</p>
        <p>It can help detect issues like:</p>
        <ul>
            <li>Insecure coding patterns</li>
            <li>Potential injection vulnerabilities</li>
            <li>Hardcoded credentials</li>
            <li>Authentication flaws</li>
            <li>Authorization issues</li>
            <li>Cryptographic problems</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def display_threat_results(result: Dict[str, Any]):
    """
    Display the results of the threat analysis

    Args:
        result (Dict[str, Any]): The threat analysis results
    """
    st.markdown("<div class='result-header'>Threat Analysis Results</div>", unsafe_allow_html=True)

    # Threat summary
    summary = result.get('summary', 'Analysis completed. See detailed results below.')
    st.markdown(f"<div class='threat-summary'>{summary}</div>", unsafe_allow_html=True)

    # Threat severity chart
    severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

    # Ensure threats list exists
    threats = result.get('threats', [])
    if not threats:
        st.info("No security threats were detected in the analysis.")
        return

    for threat in threats:
        if isinstance(threat, dict) and 'severity' in threat:
            severity = threat['severity']
            if severity in severities:
                severities[severity] += 1
            else:
                # Default to Medium if severity is not recognized
                severities["Medium"] += 1
        else:
            # Default to Medium for non-dictionary threats
            severities["Medium"] += 1

    st.bar_chart(severities)

    # Group threats by severity
    threats_by_severity = {"Critical": [], "High": [], "Medium": [], "Low": [], "Info": []}

    for threat in threats:
        if isinstance(threat, dict):
            severity = threat.get('severity', 'Medium')
            if severity in threats_by_severity:
                threats_by_severity[severity].append(threat)
            else:
                threats_by_severity['Medium'].append(threat)
        else:
            # For non-dictionary threats, create a dictionary with default values
            default_threat = {
                'title': 'Unnamed Threat',
                'description': str(threat) if threat else 'No description provided',
                'impact': 'Unknown impact',
                'severity': 'Medium'
            }
            threats_by_severity['Medium'].append(default_threat)

    # Display threats by severity (highest first)
    for severity in ["Critical", "High", "Medium", "Low", "Info"]:
        if threats_by_severity[severity]:
            st.markdown(f"<div class='severity-header severity-{severity.lower()}'>{severity} Security Threats</div>", unsafe_allow_html=True)

            for i, threat in enumerate(threats_by_severity[severity]):
                # Ensure threat has required fields
                if not isinstance(threat, dict):
                    # Skip non-dictionary threats
                    continue

                # Set default values for missing fields
                title = threat.get('title', 'Unnamed Threat')
                description = threat.get('description', 'No description provided')
                impact = threat.get('impact', 'Unknown impact')

                with st.expander(f"{severity} - {title}"):
                    st.markdown(f"**Description:** {description}")
                    st.markdown(f"**Impact:** {impact}")

                    # Location information if available
                    if 'location' in threat:
                        st.markdown(f"**Location:** {threat['location']}")
                    if 'line_numbers' in threat:
                        st.markdown(f"**Line Numbers:** {threat['line_numbers']}")

                    # Add solution steps
                    st.markdown("<div class='solution-header'>Mitigation Steps:</div>", unsafe_allow_html=True)

                    if 'mitigation' in threat and threat['mitigation']:
                        if isinstance(threat['mitigation'], list):
                            for idx, step in enumerate(threat['mitigation']):
                                st.markdown(f"{idx+1}. {step}")
                        else:
                            st.markdown(threat['mitigation'])

                    # Code snippets
                    if 'vulnerable_code' in threat and 'fixed_code' in threat:
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("**Vulnerable Code:**")
                            st.code(threat['vulnerable_code'])
                        with col2:
                            st.markdown("**Fixed Code:**")
                            st.code(threat['fixed_code'])
                    elif 'code_snippet' in threat and threat['code_snippet']:
                        st.markdown("**Vulnerable Code:**")
                        st.code(threat['code_snippet'])

                        # Generate fixed code example based on threat type
                        display_suggested_fix(threat)
                    else:
                        # If no code snippets are available, still try to suggest a fix
                        display_suggested_fix(threat)

    # Recommendations
    if 'recommendations' in result and result['recommendations']:
        st.markdown("<div class='section-header'>Recommendations</div>", unsafe_allow_html=True)
        for i, rec in enumerate(result['recommendations']):
            if isinstance(rec, dict) and 'title' in rec:
                st.markdown(f"**{i+1}. {rec['title']}**")
                if 'description' in rec:
                    st.markdown(f"{rec['description']}")
            elif isinstance(rec, str):
                st.markdown(f"**{i+1}. {rec}**")
            else:
                st.markdown(f"**{i+1}. Recommendation {i+1}**")

def display_suggested_fix(threat: Dict[str, Any]):
    """
    Display suggested fix for a security threat

    Args:
        threat (Dict[str, Any]): The threat information
    """
    # Get title with a default value if not present
    title = threat.get('title', '').lower()
    description = threat.get('description', '').lower()

    # Check for SQL Injection vulnerabilities
    if 'sql injection' in title or 'sqli' in title or 'sql injection' in description:
        st.markdown("**Suggested Fix:**")
        st.code("""def login(username, password):
    # Use parameterized queries to prevent SQL injection
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    cursor.execute(query, (username, password))
    return cursor.fetchone()""")

    # Check for XSS vulnerabilities
    elif 'xss' in title or 'cross-site scripting' in title or 'xss' in description or 'cross-site scripting' in description:
        st.markdown("**Suggested Fix:**")
        st.code("""function displayComment(comment) {
    // Sanitize input to prevent XSS
    const sanitizedComment = DOMPurify.sanitize(comment);
    document.getElementById('comments').textContent = sanitizedComment; // Use textContent instead of innerHTML
}""")

    # Check for hardcoded credentials
    elif 'hardcoded credentials' in title or 'credentials' in title or 'hardcoded' in title or 'password' in title or 'api key' in title or 'hardcoded credentials' in description:
        st.markdown("**Suggested Fix:**")
        st.code("""// Load credentials from environment variables
const apiKey = process.env.API_KEY;
const dbPassword = process.env.DB_PASSWORD;

function connectToService() {
    if (!apiKey || !dbPassword) {
        throw new Error('Missing required credentials');
    }
    return new ServiceClient(apiKey, dbPassword);
}""")
