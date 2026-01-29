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

    /* Sidebar dark style */
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
# Session state khusus untuk menyimpan path custom rules (BARU)
if 'custom_rules_path' not in st.session_state:
    st.session_state.custom_rules_path = None

# =========================
# Helper Functions
# =========================

def init_client(server_url):
    """Initialize API client"""
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
        default_url = "https://gghz.pythonanywhere.com"
        init_client(default_url)

    # Header
    st.markdown('<div class="main-header">🔍 Initial Network Analysis</div>', unsafe_allow_html=True)

    # =========================
    # Sidebar - Configuration
    # =========================
    with st.sidebar:
        st.header("⚙️ Configuration")

        # Server config
        server_url = st.text_input(
            "Server URL",
            value="https://gghz.pythonanywhere.com", 
            help="URL of Network Analyzer Server"
        )

        # Logika tombol dinamis: Berubah teks jika sudah terkoneksi
        button_label = "🔌 Re-connect to Server" if st.session_state.client else "🔌 Connect to Server"
        
        if st.button(button_label, type="primary"):
            with st.spinner("Connecting..."):
                success, result = init_client(server_url)
                if success:
                    st.success("✅ Connected to server")
                    # Notifikasi kecil di pojok layar
                    st.toast(f"Server Status: {result.get('status', 'OK')}") 
                else:
                    st.error(f"❌ Connection failed: {result}")

        # Menampilkan indikator status di bawah tombol
        if st.session_state.client:
            st.caption("🟢 Status: Connected to server")
        else:
            st.caption("🔴 Status: Disconnected")

        st.divider()

        # AbuseIPDB Configuration
        st.subheader("🛡️ AbuseIPDB")
        abuseipdb_key = st.text_input(
            "API Key",
            type="password",
            help="Optional: AbuseIPDB API key for IP reputation checking"
        )

        st.divider()

        # =========================
        # Analysis Options
        # =========================
        st.subheader("🔧 Analysis Options")

        enable_reputation = st.checkbox("Enable IP Reputation", value=True)

        # =========================
        # Rules Configuration (UPDATED LOGIC)
        # =========================
        st.subheader("📂 Rules Configuration")
        
        # Pilihan Mode Rules
        rules_mode = st.radio(
            "Pilih Sumber Rules:",
            ["Default Server Rules", "Upload Custom Rules (.yaml)"],
            horizontal=False
        )

        # Variabel Default (akan berubah jika custom dipilih)
        final_rules_path = "rules" 

        if rules_mode == "Default Server Rules":
            st.info("✅ Menggunakan rules bawaan server (Standard Detection).")
            final_rules_path = "rules"

        else: # Mode Upload Custom
            st.warning("⚠️ Upload file .yaml rules Anda.")
            
            uploaded_rules = st.file_uploader(
                "Upload File YAML Rules", 
                type=['yaml', 'yml'], 
                accept_multiple_files=True
            )

            if uploaded_rules:
                if st.button("📤 Upload Rules ke Server"):
                    if st.session_state.client:
                        with st.spinner("Mengirim rules ke server..."):
                            try:
                                # Panggil fungsi upload di client.py
                                resp = st.session_state.client.upload_custom_rules(uploaded_rules)
                                
                                # Simpan path yang diberikan server ke session state
                                st.session_state.custom_rules_path = resp['rules_path']
                                st.success(f"✅ Sukses! {resp['files_count']} file terupload.")
                                st.caption(f"Server Path: `{resp['rules_path']}`")
                                
                            except Exception as e:
                                st.error(f"Gagal upload: {e}")
                    else:
                        st.error("Mohon Connect ke Server terlebih dahulu!")

            # Cek apakah sudah ada path custom yang tersimpan di session
            if st.session_state.custom_rules_path:
                final_rules_path = st.session_state.custom_rules_path
                st.success(f"🔍 Path Rules Aktif: `{final_rules_path}`")
            elif rules_mode == "Upload Custom Rules (.yaml)":
                st.error("Wajib upload minimal 1 file rules sebelum analisis!")

    # =========================
    # If not connected
    # =========================
    if st.session_state.client is None:
        st.warning("⚠️ Please connect to server first using the sidebar")
        st.info("💡 Klik tombol 'Connect to Server' di sidebar kiri.")
        return

    # =========================
    # Main Tabs
    # =========================
    tab1, tab2, tab3, tab4 = st.tabs([
        "📤 Upload & Analyze",
        "📊 Job Status",
        "📋 Jobs History",
        "📥 Download Results"
    ])

    # =========================
    # Tab 1: Upload & Analyze
    # =========================
    with tab1:
        st.header("Upload PCAP File")

        uploaded_file = st.file_uploader(
            "Choose a PCAP file",
            type=['pcap', 'pcapng', 'cap'],
            help="Upload your network capture file for analysis"
        )

        col1, col2 = st.columns([3, 1])

        with col1:
            if uploaded_file is not None:
                st.success(f"✅ File loaded: {uploaded_file.name}")
                st.info(f"📦 Size: {uploaded_file.size / 1024 / 1024:.2f} MB")

        with col2:
            analyze_button = st.button(
                "🚀 Upload & Analyze",
                type="primary",
                disabled=uploaded_file is None
            )

        if analyze_button and uploaded_file is not None:
            # Pengecekan Rules sebelum mulai
            if rules_mode == "Upload Custom Rules (.yaml)" and not st.session_state.custom_rules_path:
                st.error("❌ Anda memilih Custom Rules tapi belum mengupload file rules!")
            else:
                temp_path = f"/tmp/{uploaded_file.name}"
                # Pastikan direktori tmp ada (untuk server linux/cloud)
                os.makedirs("/tmp", exist_ok=True)
                
                with open(temp_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())

                progress_bar = st.progress(0)
                status_text = st.empty()

                try:
                    # Upload PCAP
                    status_text.text("📤 Uploading PCAP to server...")
                    progress_bar.progress(20)

                    upload_result = st.session_state.client.upload_pcap(
                        temp_path,
                        abuseipdb_key if abuseipdb_key else None
                    )
                    job_id = upload_result['job_id']
                    st.session_state.current_job_id = job_id

                    status_text.text(f"✅ Uploaded! Job ID: {job_id}")
                    progress_bar.progress(40)
                    time.sleep(1)

                    # Start analysis (MENGGUNAKAN PATH RULES YANG BENAR)
                    status_text.text(f"🔄 Starting analysis using rules: {final_rules_path}...")
                    progress_bar.progress(50)

                    st.session_state.client.start_analysis(
                        job_id,
                        rules_dir=final_rules_path, # <--- INI KUNCINYA
                        enable_reputation=enable_reputation,
                        verbose=True
                    )

                    status_text.text("⚙️ Analysis in progress...")
                    progress_bar.progress(60)

                    # Wait for completion
                    status_text.text("⏳ Waiting for completion...")

                    def update_progress(status):
                        prog = status.get('progress', 0)
                        progress_bar.progress(60 + int(prog * 0.4))
                        status_text.text(f"⚙️ Processing: {prog}%")

                    final_status = st.session_state.client.wait_for_completion(
                        job_id,
                        poll_interval=2,
                        callback=update_progress
                    )

                    progress_bar.progress(100)
                    status_text.text("✅ Analysis completed!")

                    st.balloons()
                    st.success("🎉 Analysis completed successfully!")

                    results = st.session_state.client.get_results(job_id)
                    display_results_summary(results)

                    st.session_state.jobs_history.append({
                        'job_id': job_id,
                        'filename': uploaded_file.name,
                        'timestamp': datetime.now().isoformat(),
                        'status': 'completed'
                    })

                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")
                    progress_bar.empty()
                    status_text.empty()

                finally:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)

    # =========================
    # Tab 2: Job Status
    # =========================
    with tab2:
        st.header("Check Job Status")

        col1, col2 = st.columns([3, 1])

        with col1:
            job_id_input = st.text_input(
                "Job ID",
                value=st.session_state.current_job_id or "",
                placeholder="Enter job ID to check status"
            )

        with col2:
            st.write("")
            st.write("")
            check_button = st.button("🔍 Check Status")

        if check_button and job_id_input:
            try:
                with st.spinner("Fetching status..."):
                    status = st.session_state.client.get_status(job_id_input)
                    display_job_status(status)

                    if status['status'] == 'completed':
                        results = st.session_state.client.get_results(job_id_input)
                        st.divider()
                        display_results_summary(results)

            except Exception as e:
                st.error(f"❌ Error: {str(e)}")

    # =========================
    # Tab 3: Jobs History
    # =========================
    with tab3:
        st.header("Jobs History")

        col1, col2 = st.columns([1, 4])
        with col1:
            status_filter = st.selectbox(
                "Filter by status",
                ["All", "uploaded", "processing", "completed", "failed"]
            )

        with col2:
            if st.button("🔄 Refresh List"):
                st.rerun()

        try:
            jobs_data = st.session_state.client.list_jobs(
                status=None if status_filter == "All" else status_filter,
                limit=100
            )

            if jobs_data['jobs']:
                display_jobs_table(jobs_data['jobs'])
            else:
                st.info("No jobs found")

        except Exception as e:
            st.error(f"❌ Error loading jobs: {str(e)}")

    # =========================
    # Tab 4: Download Results
    # =========================
    with tab4:
        st.header("Download Analysis Results")

        job_id_download = st.text_input(
            "Job ID for download",
            value=st.session_state.current_job_id or "",
            key="download_job_id"
        )

        if st.button("📥 Get Download Links"):
            if job_id_download:
                try:
                    results = st.session_state.client.get_results(job_id_download)

                    st.success("✅ Files available for download:")

                    for filename in results['files']:
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.text(f"📄 {filename}")
                        with col2:
                            # Gunakan URL Server yang sedang aktif di session state, atau default
                            base_url = st.session_state.client.server_url if st.session_state.client else "http://localhost:5000"
                            download_url = f"{base_url}/api/download/{job_id_download}/{filename}"
                            st.markdown(f"[⬇️ Download]({download_url})")

                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")
            else:
                st.warning("⚠️ Please enter a Job ID")

# =========================
# Display Helpers
# =========================

def display_job_status(status):
    status_emoji = {
        'uploaded': '📤',
        'processing': '⚙️',
        'completed': '✅',
        'failed': '❌'
    }

    status_color = {
        'uploaded': 'info',
        'processing': 'warning',
        'completed': 'success',
        'failed': 'error'
    }

    current_status = status['status']
    emoji = status_emoji.get(current_status, '❓')
    color = status_color.get(current_status, 'info')

    st.markdown(f'<div class="status-box status-{color}">', unsafe_allow_html=True)
    st.markdown(f"### {emoji} Status: {current_status.upper()}")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Job ID", status['job_id'][:16] + "...")
        st.metric("Filename", status.get('filename', 'N/A'))

    with col2:
        st.metric("Created", status.get('created_at', 'N/A')[:19])
        if 'size' in status:
            st.metric("File Size", f"{status['size'] / 1024 / 1024:.2f} MB")

    with col3:
        if 'progress' in status:
            st.metric("Progress", f"{status['progress']}%")
            st.progress(status['progress'] / 100)

    if current_status == 'failed' and 'error' in status:
        st.error(f"Error: {status['error']}")

    st.markdown('</div>', unsafe_allow_html=True)


def display_results_summary(results):
    st.subheader("📊 Analysis Results")

    res = results['results']

   
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("📦 Total Packets", f"{res.get('total_packets', 0):,}")
    with col2:
        st.metric("⚠️ Alerts", f"{res.get('alerts_generated', 0):,}")
    with col3:
        st.metric("🔍 Rules Applied", f"{res.get('rules_applied', 0):,}")
    with col4:
        st.metric("🚨 Malicious IPs", f"{res.get('malicious_ips_found', 0):,}")

  
    st.divider()
    st.subheader("🚨 Alerts Detected")

    alerts = results.get("alerts", [])

    if not alerts:
        st.success("✅ No alerts detected by current rules.")
        return

    alerts_df = pd.DataFrame(alerts)

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts_df["severity_rank"] = alerts_df["severity"].map(severity_rank).fillna(9)
    alerts_df = alerts_df.sort_values("severity_rank")

    st.dataframe(
        alerts_df[
            ["alert_id", "rule_name", "severity", "packet_index", "protocol", "src_ip", "dst_ip"]
        ],
        use_container_width=True,
        height=300
    )

 
    st.divider()
    st.subheader("🔍 Alert Detail")

    alert_ids = alerts_df["alert_id"].tolist()

    selected_alert = st.selectbox(
        "Pilih Alert untuk melihat detail:",
        options=alert_ids
    )

    alert_details = results.get("alert_details", {})

    if selected_alert and selected_alert in alert_details:
        detail = alert_details[selected_alert]

        with st.expander(f"📄 Detail Alert {selected_alert}", expanded=True):
            st.markdown("### 🧾 Rule Information")
            st.json(detail.get("rule", {}))

            st.markdown("### 📦 Packet Information")
            st.json(detail.get("packet", {}))

            st.markdown("### 📜 Payload Snippet")
            payload = detail.get("payload", {})
            st.code(payload.get("snippet", ""), language="text")
            st.caption(f"Payload length: {payload.get('length', 0)} bytes")

   
    if 'top_rules_matched' in res and res['top_rules_matched']:
        st.divider()
        st.subheader("🎯 Top Rules Matched")

        rules_df = pd.DataFrame(
            list(res['top_rules_matched'].items()),
            columns=['Rule', 'Matches']
        )
        st.bar_chart(rules_df.set_index('Rule'))

  
    if 'protocols' in res and res['protocols']:
        st.divider()
        st.subheader("🌐 Protocol Distribution")

        proto_df = pd.DataFrame(
            list(res['protocols'].items()),
            columns=['Protocol', 'Count']
        )
        st.bar_chart(proto_df.set_index('Protocol'))


def display_jobs_table(jobs):
    jobs_data = []
    for job in jobs:
        jobs_data.append({
            'Job ID': job['job_id'],
            'Filename': job.get('filename', 'N/A'),
            'Status': job['status'],
            'Created': job.get('created_at', 'N/A')[:19],
            'Size (MB)': f"{job.get('size', 0) / 1024 / 1024:.2f}" if 'size' in job else 'N/A'
        })

    df = pd.DataFrame(jobs_data)

    def color_status(val):
        colors = {
            'completed': 'background-color: #d4edda',
            'processing': 'background-color: #fff3cd',
            'failed': 'background-color: #f8d7da',
            'uploaded': 'background-color: #d1ecf1'
        }
        return colors.get(val, '')

    styled_df = df.style.applymap(color_status, subset=['Status'])
    st.dataframe(styled_df, use_container_width=True)


if __name__ == "__main__":
    main()
