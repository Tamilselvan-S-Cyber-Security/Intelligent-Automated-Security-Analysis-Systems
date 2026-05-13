"""
CyberWolf Security Analyzer - Modular Version

This is the main entry point for the CyberWolf Security Analyzer application.
It uses a modular architecture for better organization and maintainability.
"""

import streamlit as st
import wolf_api
import security_analyzer
import web_scraper
import attack_simulator
import re
from typing import Optional

# Import modules
from modules.wolf_core import (
    encrypt_api_key, decrypt_api_key, generate_api_key, 
    calculate_security_score, group_findings_by_category, generate_report_summary
)
from modules.ui_components import (
    setup_page_config, load_css, load_js, display_header, 
    setup_sidebar, display_fast_results
)
from modules.website_analyzer import handle_website_analysis
from modules.threat_detector import handle_threat_detection

# Initialize session state for API key management
if 'api_key_generated' not in st.session_state:
    st.session_state.api_key_generated = False
if 'api_key' not in st.session_state:
    st.session_state.api_key = None
if 'encrypted_api_key' not in st.session_state:
    st.session_state.encrypted_api_key = None
if 'key_method' not in st.session_state:
    st.session_state.key_method = "default"

def get_api_key() -> Optional[str]:
    """
    Get API key from session state and decrypt it.
    """
    if not st.session_state.encrypted_api_key:
        return None
        
    try:
        return decrypt_api_key(st.session_state.encrypted_api_key)
    except Exception as e:
        st.error(f"Error getting API key: {str(e)}")
        return None

def main():
    """Main application entry point"""
    # Set up the page
    setup_page_config()
    load_css()
    display_header()
    
    # Set up the sidebar and get the selected tool
    selected_tool = setup_sidebar(get_api_key, encrypt_api_key, generate_api_key)
    
    # Main content area
    st.markdown("<div class='glass-container main-content'>", unsafe_allow_html=True)
    
    # Check if API key is set
    if 'encrypted_api_key' not in st.session_state:
        st.warning("⚠️ Please enter your API Key in the sidebar to use the analysis tools.")
        st.markdown("""
        <div class='info-box'>
            <h3>🔑 About API Key</h3>
            <p>API Key is our enhanced version, specialized for advanced cybersecurity analysis.</p>
            <p>This powerful AI model identifies security threats, vulnerabilities, and provides detailed remediation steps.</p>
            <p>To get started, you'll need to obtain a API key and enter it in the sidebar.</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Initialize Wolf API client
        api_client = wolf_api.WolfAPI(get_api_key())
        
        # Website Security Analysis
        if selected_tool == "Website Security Analysis":
            handle_website_analysis(api_client)
        
        # Security Threat Detection
        elif selected_tool == "Security Threat Detection":
            handle_threat_detection(api_client, security_analyzer)
        
        # Web Application Scan
        elif selected_tool == "Web Application Scan":
            st.subheader("🕸️ Web Application Security Scan")
            st.info("This module is being loaded from the original wolf.py file. It will be modularized in a future update.")
            # TODO: Implement modular version of Web Application Scan
        
        # Background Process Analysis
        elif selected_tool == "Background Process Analysis":
            st.subheader("⚙️ Background Process & Service Analysis")
            st.info("This module is being loaded from the original wolf.py file. It will be modularized in a future update.")
            # TODO: Implement modular version of Background Process Analysis
        
        # Attack Simulation
        elif selected_tool == "Attack Simulation":
            st.subheader("🎯 Attack Simulation")
            st.info("This module is being loaded from the original wolf.py file. It will be modularized in a future update.")
            # TODO: Implement modular version of Attack Simulation
        
        # Advanced Features
        elif selected_tool == "Advanced Features":
            st.subheader("🔬 Advanced Security Features")
            st.info("This module is being loaded from the original wolf.py file. It will be modularized in a future update.")
            # TODO: Implement modular version of Advanced Features
        
        # Source Code Analysis
        elif selected_tool == "Source Code Analysis":
            st.subheader("📝 Source Code Security Analysis")
            st.info("This module is being loaded from the original wolf.py file. It will be modularized in a future update.")
            # TODO: Implement modular version of Source Code Analysis
        
        # Website Cloning
        elif selected_tool == "Website Cloning":
            st.subheader("🔄 Website Cloning & Analysis")
            st.info("This module is being loaded from the original wolf.py file. It will be modularized in a future update.")
            # TODO: Implement modular version of Website Cloning

    # Close the main content div
    st.markdown("</div>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
