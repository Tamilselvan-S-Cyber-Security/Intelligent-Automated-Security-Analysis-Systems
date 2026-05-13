import os
import sys

# Ensure the current directory is in the path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

# Import the main Streamlit application
try:
    import wolf
except Exception as e:
    import streamlit as st
    st.error(f"Failed to load the main application (wolf.py): {str(e)}")
    st.exception(e)
