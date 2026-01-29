"""
Network Analyzer Client - Streamlit GUI
Optimized for Streamlit Cloud & Python 3.13
"""

import streamlit as st
import time
import os
from datetime import datetime
import json
import pandas as pd
# Pastikan file client.py ada di folder yang sama
try:
    from client import NetworkAnalyzerClient
except ImportError:
    st.error("File 'client.py' tidak ditemukan! Pastikan file tersebut ada di folder yang sama dengan app.py")

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
    .status-box { padding: 1rem; border-radius: 5px; margin: 1rem 0; }
    .status-success { background-color: #d4edda; border-left: 4px solid #28a745; color: #155724; }
    .status-warning { background-color: #fff3cd; border-left: 4px solid #ffc107; color: #856404; }
    .status-error { background-color: #f8d7da; border-left: 4px solid #dc3545; color: #721c24; }
    .status-info { background-color: #d1ecf1; border-left: 4px solid #17a2b8; color: #0c5460; }
    .metric-card {
        background-color: #ffffff;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        border: 1px solid #e1e4e8;
    }
</style>
""", unsafe_allow_html=True)

# =========================
# Session State & Caching
# =========================
if 'client' not in st.session_state:
    st.session_state.client = None
if 'current_job_id' not in st.session_state:
    st.session_state.current_job_id = None
if 'custom_rules_path' not in st.session_state:
    st.session_state.custom_rules_path = None

@st.cache_resource
def get_client(server_url):
    """Fungsi singleton untuk menjaga koneksi client tetap stabil"""
    try:
        client = NetworkAnalyzerClient(server_url)
        return client
    except Exception:
        return None

# =========================
# Display Helpers (Optimized)
# =========================

def display_job_status(status):
    status_map = {
        'uploaded': ('📤', 'info'),
        'processing': ('⚙️', 'warning'),
        'completed': ('✅', 'success'),
        'failed': ('❌', 'error')
    }
    
    current_status = status.get('status', 'unknown')
    emoji, color_class = status_map.get(current_status, ('❓', 'info'))

    st.markdown(f'<div class="status-box status-{color_class}">', unsafe_allow_html=True)
    st.markdown(f"### {emoji} Status: {current_status.upper()}")
    
    c1, c2, c3 = st.columns(3)
    with c1:
        st.write(f"**Job ID:** `{status['job_id'][:16]}...`" if 'job_id' in status else "**Job ID:** N/A")
        st.write(f"**Filename:** {status.get('filename', 'N/A')}")
    with c2:
        st.write(f"**Created:** {status.get('created_at', 'N/A')[:19]}")
        if 'size' in status:
            st.write(f"**Size:** {status['size'] / (1024*1024):.2f} MB")
    with c3:
        if 'progress' in status:
            st.write(f"**Progress:** {status['progress']}%")
            st.progress(status['progress'] / 100)
    
    if current_status == 'failed' and 'error' in status:
        st.error(f"Detail Error: {status['error']}")
    st.markdown('</div>', unsafe_allow_html=True)

def display_results_summary(results):
    res = results.get('results', {})
    
    st.subheader("📊 Analysis Summary")
    col1, col2, col3, col4 = st.columns(4)
    
    metrics = [
        ("📦 Total Packets", res.get('total_packets', 0)),
        ("⚠️ Alerts", res.get('alerts_generated', 0)),
        ("🔍 Rules Applied", res.get('rules_applied', 0)),
        ("🚨 Malicious IPs", res.get('malicious_ips_found', 0))
    ]
    
    cols = [col1, col2, col3, col4]
    for i, (label, val) in enumerate(metrics):
        with cols[i]:
            st.markdown(f'<div class="metric-card">', unsafe_allow_html=True)
            st.metric(label, f"{val:,}")
            st.markdown('</div>', unsafe_allow_html=True)

    if results.get('logs'):
        with st.expander("📄 Detail Analysis Logs", expanded=False):
            st.code("\n".join(results['logs']), language="log")

    if 'protocols' in res:
        st.subheader("🌐 Protocol Distribution")
        proto_df = pd.DataFrame(list(res['protocols'].items()), columns=['Protocol', 'Count'])
        st.bar_chart(proto_df.set_index('Protocol'))

def display_jobs_table(jobs):
    df = pd.DataFrame(jobs)
    if df.empty:
        st.info("Belum ada riwayat pekerjaan.")
        return

    # Pembersihan data untuk tabel
    display_df = pd.DataFrame({
        'Job ID': df['job_id'],
        'Filename': df.get('filename', 'N/A'),
        'Status': df['status'],
        'Time': df.get('created_at', 'N/A').str[:16]
    })

    def color_status(val):
        colors = {
            'completed': 'background-color: #d4edda; color: #155724;',
            'processing': 'background-color: #fff3cd; color: #856404;',
            'failed': 'background-color: #f8d7da; color: #721c24;',
            'uploaded': 'background-color: #d1ecf1; color: #0c5460;'
        }
        return colors.get(val, '')

    # FIX: Menggunakan .map() sebagai pengganti .applymap() untuk Python 3.13/Pandas 2.x
    styled_df = display_df.style.map(color_status, subset=['Status'])
    st.dataframe(styled_df, use_container_width=True)

# =========================
# Main Application Logic
# =========================

def main():
    st.markdown('<div class="main-header">🔍 Initial Network Analysis</div>', unsafe_allow_html=True)

    # Sidebar
    with st.sidebar:
        st.header("⚙️ Settings")
        server_url = st.text_input("Server URL", value="https://gghz.pythonanywhere.com")
        
        if st.button("🔌 Connect/Sync Server", type="primary"):
            client = get_client(server_url)
            if client:
                st.session_state.client = client
                st.success("Connected!")
            else:
                st.error("Gagal terhubung ke server.")

        if st.session_state.client:
            st.caption("🟢 Status: Connected")
        else:
            st.caption("🔴 Status: Disconnected")
        
        st.divider()
        st.subheader("🔧 Options")
        enable_reputation = st.checkbox("IP Reputation", value=True)
        rules_mode = st.radio("Rules Source:", ["Server Default", "Custom YAML"])
        
        final_rules_path = "rules"
        if rules_mode == "Custom YAML":
            uploaded_rules = st.file_uploader("Upload Rules", type=['yaml', 'yml'], accept_multiple_files=True)
            if uploaded_rules and st.button("📤 Push Rules"):
                try:
                    resp = st.session_state.client.upload_custom_rules(uploaded_rules)
                    st.session_state.custom_rules_path = resp['rules_path']
                    st.success("Rules uploaded!")
                except Exception as e:
                    st.error(f"Upload fail: {e}")
            
            if st.session_state.custom_rules_path:
                final_rules_path = st.session_state.custom_rules_path

    if not st.session_state.client:
        st.warning("Silakan hubungkan ke server melalui sidebar terlebih dahulu.")
        return

    tab1, tab2, tab3, tab4 = st.tabs(["📤 Upload", "📊 Status", "📋 History", "📥 Download"])

    with tab1:
        st.header("Analyze New PCAP")
        up_file = st.file_uploader("Pilih file PCAP", type=['pcap', 'pcapng', 'cap'])
        
        if up_file and st.button("🚀 Start Analysis"):
            # Proses Upload & Analisis
            with st.status("Processing...", expanded=True) as status:
                try:
                    # Simpan file sementara
                    tmp_name = f"temp_{up_file.name}"
                    with open(tmp_name, "wb") as f:
                        f.write(up_file.getbuffer())
                    
                    st.write("Uploading to server...")
                    up_res = st.session_state.client.upload_pcap(tmp_name)
                    jid = up_res['job_id']
                    st.session_state.current_job_id = jid
                    
                    st.write("Starting engine...")
                    st.session_state.client.start_analysis(jid, rules_dir=final_rules_path, enable_reputation=enable_reputation)
                    
                    # Waiting loop
                    final_data = st.session_state.client.wait_for_completion(jid, poll_interval=2)
                    status.update(label="Analysis Completed!", state="complete")
                    st.balloons()
                    
                    # Tampilkan hasil singkat
                    res_data = st.session_state.client.get_results(jid)
                    display_results_summary(res_data)
                    
                except Exception as e:
                    st.error(f"Error: {e}")
                finally:
                    if os.path.exists(tmp_name): os.remove(tmp_name)

    with tab2:
        jid_check = st.text_input("Job ID", value=st.session_state.current_job_id or "")
        if st.button("🔍 Refresh Status") and jid_check:
            try:
                s = st.session_state.client.get_status(jid_check)
                display_job_status(s)
                if s['status'] == 'completed':
                    r = st.session_state.client.get_results(jid_check)
                    display_results_summary(r)
            except Exception as e:
                st.error(e)

    with tab3:
        st.header("Recent Jobs")
        if st.button("🔄 Reload History"):
            try:
                history = st.session_state.client.list_jobs(limit=20)
                display_jobs_table(history['jobs'])
            except Exception as e:
                st.error(e)

    with tab4:
        st.header("Downloads")
        jid_dl = st.text_input("Enter Job ID", value=st.session_state.current_job_id or "", key="dl_input")
        if jid_dl and st.button("📦 Get Files"):
            try:
                results = st.session_state.client.get_results(jid_dl)
                for fname in results.get('files', []):
                    url = f"{st.session_state.client.server_url}/api/download/{jid_dl}/{fname}"
                    st.markdown(f"📄 {fname} [⬇️ Download]({url})")
            except Exception as e:
                st.error(e)

if __name__ == "__main__":
    main()
