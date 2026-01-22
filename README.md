
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

Update database
    
    python3    core/intel_updater.py

Struktur project

    basic-network-analysis        .
    ├── client/              # Antarmuka Pengguna (Streamlit)
    │   ├── app.py           # Main UI Dashboard
    │   └── client.py        # API Wrapper untuk komunikasi server
    ├── core/                # Mesin Analisis Inti (Backend Logic)
    │   ├── engine.py        # Rule processing engine
    │   ├── parser.py        # Packet decomposition & feature extraction
    │   ├── reader.py        # PCAP/PCAPNG file reader
    │   ├── reputation.py    # IP threat intelligence logic
    │   └── writer.py        # Output & Alert logger
    ├── data/                # Database Pendukung
    │   └── threat_intel.db  # Local threat database
    ├── rules/               # Definisi Deteksi Serangan (YAML)
    │   ├── malware_behavior.yaml
    │   ├── network_attacks.yaml
    │   └── web_attacks.yaml
    ├── server/              # REST API Server (Flask)
    │   ├── analyzer.py      # Analyzer coordinator
    │   ├── app.py           # API Endpoints
    │   └── storage.py       # Upload & output management
    ├── requirements.txt     # Daftar dependensi Python
    └── README.md            # Dokumentasi proyek

