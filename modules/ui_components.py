"""
UI Components for the CyberWolf Security Analyzer

This module contains UI components and helper functions for the Streamlit interface.
"""

import streamlit as st
import json
import os
from datetime import datetime
import pyperclip
from typing import Dict, Any, List

def load_css():
    """Load custom CSS styles for the application"""
    with open("style.css", "r", encoding="utf-8") as f:
        css = f.read()
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
        
def load_js():
    """Load JavaScript for the application"""
    with open("carousel.js", "r") as f:
        js = f.read()
        st.markdown(f"""
        <script>
            {js}
        </script>
        """, unsafe_allow_html=True)

def setup_page_config():
    """Set up the page configuration for the Streamlit app"""
    st.set_page_config(
        page_title="Cyber Wolf Security Analyzer",
        page_icon="🐺",
        layout="wide",
        initial_sidebar_state="expanded"
    )

def display_header():
    """Display the main application header"""
    st.markdown("<div class='glass-header'><h1>🐺 Cyber Wolf Security Analyzer</h1></div>", unsafe_allow_html=True)
    
    st.markdown("""
    <div class='glass-container'>
        <p>Advanced Cybersecurity Analysis Platform powered by Wolf API</p>
        <p>Elite Security Analysis for Websites, Applications, Code, and System Configurations</p>
        <p>Developed by the Cyber Wolf Team</p>
    </div>
    """, unsafe_allow_html=True)

def display_fast_results(results):
    """
    Display analysis results quickly and clearly
    
    Args:
        results (List[Dict]): List of scan results
    """
    from modules.wolf_core import calculate_security_score
    
    # Security score
    score = calculate_security_score(results)
    st.markdown(f"""
    <div class='security-score'>
        <h3>Security Score: {score}/100</h3>
        <div class='score-bar'>
            <div class='score-fill' style='width: {score}%'></div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Critical findings first
    st.markdown("<h3>⚠️ Critical Issues</h3>", unsafe_allow_html=True)
    for result in results:
        for issue in result.get('issues', []):
            if issue.get('priority') == 'Critical':
                st.markdown(f"""
                <div class='issue-card critical'>
                    <h4>{issue['title']}</h4>
                    <p>{issue['description']}</p>
                    <div class='recommendation'>
                        <strong>Fix:</strong> {issue['recommendation']}
                    </div>
                </div>
                """, unsafe_allow_html=True)
    
    # Other findings
    st.markdown("<h3>🔍 Other Findings</h3>", unsafe_allow_html=True)
    for result in results:
        for issue in result.get('issues', []):
            if issue.get('priority') != 'Critical':
                st.markdown(f"""
                <div class='issue-card'>
                    <h4>{issue['title']}</h4>
                    <p>{issue['description']}</p>
                    <div class='recommendation'>
                        <strong>Fix:</strong> {issue['recommendation']}
                    </div>
                </div>
                """, unsafe_allow_html=True)

def export_analysis_report(results):
    """
    Export analysis report in various formats
    
    Args:
        results (List[Dict]): List of scan results
    """
    from modules.wolf_core import generate_report_summary
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'findings': results,
        'summary': generate_report_summary(results)
    }
    
    # Save as JSON
    with open('security_analysis_report.json', 'w') as f:
        json.dump(report, f, indent=4)
    
    st.success("✅ Report exported successfully!")

def copy_summary_to_clipboard(results):
    """
    Copy summary to clipboard
    
    Args:
        results (List[Dict]): List of scan results
    """
    from modules.wolf_core import generate_report_summary
    
    summary = generate_report_summary(results)
    pyperclip.copy(summary)
    st.success("✅ Summary copied to clipboard!")

def setup_sidebar(get_api_key_func, encrypt_api_key_func, generate_api_key_func):
    """
    Set up the sidebar for the application
    
    Args:
        get_api_key_func: Function to get the API key
        encrypt_api_key_func: Function to encrypt the API key
        generate_api_key_func: Function to generate a new API key
        
    Returns:
        str: The selected tool
    """
    with st.sidebar:
        st.markdown("<div class='glass-sidebar-header'>🔐 API Configuration</div>", unsafe_allow_html=True)
        
        # API key management section
        api_key_tab1, api_key_tab2 = st.tabs(["Use Existing Key", "Generate New Key"])
        
        with api_key_tab1:
            # Get API key from session state
            api_key = get_api_key_func()
            
            if api_key:
                st.success("✅ API Key is configured")
                st.info(f"Key Method: {st.session_state.key_method}")
                if st.button("Clear API Key"):
                    st.session_state.pop('api_key', None)
                    st.session_state.pop('encrypted_api_key', None)
                    st.session_state.api_key_generated = False
                    st.session_state.key_method = "default"
                    st.rerun()
            else:
                # API key input
                api_key = st.text_input("Enter API Key", 
                                      type="password", 
                                      help="Your API key will be encrypted before storage")
                
                if api_key:
                    encrypted_key = encrypt_api_key_func(api_key)
                    if encrypted_key:
                        st.session_state.encrypted_api_key = encrypted_key
                        st.session_state.key_method = "manual"
                        st.success("✅ API Key saved and encrypted")
                        st.rerun()
        
        with api_key_tab2:
            if not st.session_state.api_key_generated:
                key_method = st.selectbox(
                    "Select Key Generation Method",
                    ["default", "method1", "method2", "method3", "method4"],
                    help="Choose how to generate your API key"
                )
                
                if st.button("Generate New API Key"):
                    api_key, encrypted_key = generate_api_key_func(key_method)
                    if api_key and encrypted_key:
                        st.session_state.encrypted_api_key = encrypted_key
                        st.success("✅ New API Key generated and encrypted")
                        st.code(api_key, language="text")
                        st.warning("⚠️ Save this key securely. It won't be shown again.")
            else:
                st.info("API key has already been generated. Clear the existing key to generate a new one.")
        
        st.markdown("<hr>", unsafe_allow_html=True)
        
        # Navigation
        st.markdown("<div class='glass-sidebar-header'>🧭 Navigation</div>", unsafe_allow_html=True)
        
        # Add Advanced Bug Finder button
        if st.button("Advanced Bug Finder 🐛", key="bug_finder_button"):
            st.markdown('<meta http-equiv="refresh" content="0;url=http://127.0.0.1:840">', unsafe_allow_html=True)
        
        selected_tool = st.radio(
            "Select Analysis Tool",
            ["Website Security Analysis", "Security Threat Detection", "Web Application Scan", "Background Process Analysis", 
             "Attack Simulation", "Advanced Features", "Source Code Analysis", "Website Cloning"]
        )
        
        st.markdown("<hr>", unsafe_allow_html=True)
        st.markdown("<div class='glass-sidebar-footer'>Created by Cyber Wolf Team<br>Version 1.0.0</div>", unsafe_allow_html=True)
        
        return selected_tool
