"""
Network Analyzer Client - Streamlit GUI
Interactive web-based client untuk Network Analyzer Server
"""

import streamlit as st
import time
import os
from datetime import datetime
import json
from client import NetworkAnalyzerClient
import pandas as pd

# =========================
# Page configuration
# =========================
st.set_page_config(
    page_title="Initial Network Analysis",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =========================
# Custom CSS (Enhanced UI)
# =========================
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        text-align: center;
        padding: 1rem;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }

    .status-box {
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .status-success {
        background-color: #d4edda;
        border-left: 4px solid #28a745;
    }
    .status-warning {
        background-color: #fff3cd;
        border-left: 4px solid #ffc107;
    }
    .status-error {
        background-color: #f8d7da;
        border-left: 4px solid #dc3545;
    }
    .status-info {
        background-color: #d1ecf1;
        border-left: 4px solid #17a2b8;
    }

    .metric-card {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    section[data-testid="stSidebar"] {
        background-color: #0f172a;
    }
    section[data-testid="stSidebar"] * {
        color: #e5e7eb;
    }

    .stButton>button {
        border-radius: 8px;
        height: 3em;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# =========================
# Session State
# =========================
if 'client' not in st.session_state:
    st.session_state.client = None
if 'current_job_id' not in st.session_state:
    st.session_state.current_job_id = None
if 'jobs_history' not in st.session_state:
    st.session_state.jobs_history = []
if 'custom_rules_path' not in st.session_state:
    st.session_state.custom_rules_path = None

# =========================
# Helper Functions
# =========================

def init_client(server_url):
    try:
        client = NetworkAnalyzerClient(server_url)
        health = client.health_check()
        st.session_state.client = client
        return True, health
    except Exception as e:
        return False, str(e)

# =========================
# Main App
# =========================

def main():
    if st.session_state.client is None:
        init_client("https://gghz.pythonanywhere.com")

    st.markdown('<div class="main-header">🔍 Initial Network Analysis</div>', unsafe_allow_html=True)

    # =========================
    # Sidebar
    # =========================
    with st.sidebar:
        st.header("⚙️ Configuration")

        server_url = st.text_input(
            "Server URL",
            value="https://gghz.pythonanywhere.com"
        )

        button_label = "🔌 Re-connect to Server" if st.session_state.client else "🔌 Connect to Server"

        if st.button(button_label, type="primary"):
            with st.spinner("Connecting..."):
                success, result = init_client(server_url)
                if success:
                    st.success("✅ Connected to server")
                    st.toast(f"Server Status: {result.get('status', 'OK')}")
                else:
                    st.error(f"❌ Connection failed: {result}")

        st.caption("🟢 Connected" if st.session_state.client else "🔴 Disconnected")
        st.divider()

        st.subheader("🛡️ AbuseIPDB")
        abuseipdb_key = st.text_input("API Key", type="password")

        st.divider()
        st.subheader("🔧 Analysis Options")
        enable_reputation = st.checkbox("Enable IP Reputation", value=True)

        st.subheader("📂 Rules Configuration")
        rules_mode = st.radio(
            "Pilih Sumber Rules:",
            ["Default Server Rules", "Upload Custom Rules (.yaml)"]
        )

        final_rules_path = "rules"

        if rules_mode == "Upload Custom Rules (.yaml)":
            uploaded_rules = st.file_uploader(
                "Upload YAML Rules",
                type=['yaml', 'yml'],
                accept_multiple_files=True
            )

            if uploaded_rules and st.button("📤 Upload Rules ke Server"):
                if st.session_state.client:
                    resp = st.session_state.client.upload_custom_rules(uploaded_rules)
                    st.session_state.custom_rules_path = resp['rules_path']
                    st.success("Rules uploaded")

            if st.session_state.custom_rules_path:
                final_rules_path = st.session_state.custom_rules_path
                st.info(f"Active Rules: {final_rules_path}")
            else:
                st.warning("Upload rules terlebih dahulu")

    if not st.session_state.client:
        st.warning("Connect ke server terlebih dahulu")
        return

    tab1, tab2, tab3, tab4 = st.tabs([
        "📤 Upload & Analyze",
        "📊 Job Status",
        "📋 Jobs History",
        "📥 Download Results"
    ])

    # =========================
    # TAB 3: Jobs History (INI YANG FIX)
    # =========================
    with tab3:
        st.header("Jobs History")

        jobs_data = st.session_state.client.list_jobs(limit=100)
        if jobs_data['jobs']:
            display_jobs_table(jobs_data['jobs'])
        else:
            st.info("No jobs found")

# =========================
# Display Helpers
# =========================

def display_jobs_table(jobs):
    rows = []
    for job in jobs:
        rows.append({
            "Job ID": job["job_id"],
            "Filename": job.get("filename", "N/A"),
            "Status": job["status"],
            "Created": job.get("created_at", "N/A")[:19],
            "Size (MB)": f"{job.get('size', 0) / 1024 / 1024:.2f}"
        })

    df = pd.DataFrame(rows)

    def color_status(val):
        return {
            "completed": "background-color: #d4edda",
            "processing": "background-color: #fff3cd",
            "failed": "background-color: #f8d7da",
            "uploaded": "background-color: #d1ecf1",
        }.get(val, "")

   
    styled_df = df.style.map(color_status, subset=["Status"])
    st.dataframe(styled_df, use_container_width=True)

# =========================
# Run App
# =========================
if __name__ == "__main__":
    main()
