#!/bin/bash
# Run Streamlit GUI Client

echo "Starting Network Analyzer GUI Client..."
echo "========================================="
echo ""
echo "Make sure the server is running at http://localhost:5000"
echo ""

streamlit run client/app.py --server.port 8501 --server.address localhost
