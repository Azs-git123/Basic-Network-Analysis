🌍 Quick Access (Live Demo)

Anda dapat mencoba aplikasi ini secara langsung tanpa instalasi melalui tautan berikut:

    Live Web App: https://basic-network-analysis.streamlit.app
🛠️ Deployment Guide
Option 1: Manual Run (Local / Linux)

Gunakan opsi ini jika ingin menjalankan aplikasi di mesin lokal

    Clone & Setup Environment
    git clone https://github.com/Azs-git123/Basic-Network-Analysis/
    cd Basic-Network-Analysis
    pip install -r requirements.txt

Jalankan server
    
    python server/app.py

Jalankan Client

    streamlit run client/app.py

Struktur project

    Basic-Network-Analysis
    ├── client/              # Streamlit Web Interface
    │   └── app.py           # Main UI Logic
    ├── server/              # Flask Backend Engine
    │   ├── app.py           # REST API Endpoints
    │   ├── analyzer.py      # Core Analysis Logic
    │   └── core/            # Parser & Engine Modules
    ├── rules/               # Detection Rules (YAML)
    ├── uploads/             # Temporary PCAP Storage
    └── outputs/             # Analysis Reports & Logs
