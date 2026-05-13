"""
Website Security Analysis Module

This module contains functions for analyzing website security.
"""

import streamlit as st
import os
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Any
from report_generator import ReportGenerator
from modules.ui_components import display_fast_results

def handle_website_analysis(api_client):
    """
    Handle the website security analysis workflow
    
    Args:
        api_client: The API client for making security analysis requests
    """
    st.markdown("<div class='modern-section'>", unsafe_allow_html=True)
    st.markdown("<h2>🔍 Website Security Analysis</h2>", unsafe_allow_html=True)
    
    url = st.text_input("Enter Website URL", placeholder="https://example.com")
    
    if url:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        scan_options = st.multiselect(
            "Select Scan Types",
            ["Vulnerabilities", "SSL/TLS", "Headers", "Content Security"],
            default=["Vulnerabilities", "SSL/TLS"]
        )
        
        if st.button("🚀 Start Analysis"):
            with st.spinner("🔍 Analyzing..."):
                try:
                    progress_bar = st.progress(0)
                    results = []
                    
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        futures = [executor.submit(api_client.analyze_website, url, scan_type=scan) 
                                 for scan in scan_options]
                        
                        for i, future in enumerate(concurrent.futures.as_completed(futures)):
                            results.append(future.result())
                            progress_bar.progress((i + 1) * 100 // len(futures))
                    
                    # Display results
                    display_fast_results(results)
                    
                    # Generate reports
                    with st.spinner("📊 Generating Reports..."):
                        report_generator = ReportGenerator(results, url)
                        html_report, pdf_report = report_generator.generate_reports()
                        
                        st.markdown("### 📑 Report Generation")
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.download_button(
                                label="📥 Download HTML Report",
                                data=html_report,
                                file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                                mime="text/html"
                            )
                        
                        with col2:
                            with open(pdf_report, "rb") as f:
                                st.download_button(
                                    label="📥 Download PDF Report",
                                    data=f,
                                    file_name=os.path.basename(pdf_report),
                                    mime="application/pdf"
                                )
                        
                        try:
                            os.remove(pdf_report)
                        except:
                            pass
                    
                except Exception as e:
                    st.error(f"❌ Analysis error: {str(e)}")

def analyze_website_security(api_client, url: str, scan_options: List[str]) -> List[Dict[str, Any]]:
    """
    Analyze website security using parallel processing
    
    Args:
        api_client: The API client for making security analysis requests
        url (str): The URL to analyze
        scan_options (List[str]): List of scan types to perform
        
    Returns:
        List[Dict[str, Any]]: List of scan results
    """
    results = []
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(api_client.analyze_website, url, scan_type=scan) 
                 for scan in scan_options]
        
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    
    return results
