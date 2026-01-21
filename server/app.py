#!/usr/bin/env python3
import sys
import os

# =========================================================
# FIX 1: Konfigurasi Path untuk PythonAnywhere
# =========================================================
project_home = '/home/gghz/Basic-Network-Analysis'
if project_home not in sys.path:
    sys.path.append(project_home)

from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
import threading
import uuid
from datetime import datetime
from analyzer import PCAPAnalyzer
from storage import StorageManager

app = Flask(__name__)

# =========================================================
# FIX 2: Matikan JSON Sorting (Mencegah Crash TypeError)
# =========================================================
app.json.sort_keys = False

app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB
app.config['UPLOAD_FOLDER'] = os.path.join(project_home, 'uploads')
app.config['OUTPUT_FOLDER'] = os.path.join(project_home, 'outputs')

# Initialize storage manager
storage = StorageManager(
    upload_dir=app.config['UPLOAD_FOLDER'],
    output_dir=app.config['OUTPUT_FOLDER']
)

# Job tracking
jobs = {}
jobs_lock = threading.Lock()

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'service': 'Network Analyzer Server',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/upload', methods=['POST'])
def upload_pcap():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    job_id = str(uuid.uuid4())
    filename = secure_filename(file.filename)
    filepath = storage.save_upload(job_id, file, filename)

    abuseipdb_key = request.form.get('abuseipdb_key', None)

    with jobs_lock:
        jobs[job_id] = {
            'job_id': job_id,
            'filename': filename,
            'filepath': filepath,
            'size': os.path.getsize(filepath),
            'status': 'uploaded',
            'created_at': datetime.now().isoformat(),
            'abuseipdb_key': abuseipdb_key,
            'progress': 0,
            'logs': [], # Inisialisasi awal agar tidak None
            'results': None,
            'error': None
        }

    return jsonify({'job_id': job_id, 'status': 'uploaded'}), 201

@app.route('/api/analyze/<job_id>', methods=['POST'])
def start_analysis(job_id):
    with jobs_lock:
        if job_id not in jobs:
            return jsonify({'error': 'Job not found'}), 404
        job = jobs[job_id]
        if job['status'] != 'uploaded':
            return jsonify({'error': 'Invalid job status'}), 400

        options = request.get_json() or {}
        rules_dir = options.get('rules_dir', 'rules')
        enable_reputation = options.get('enable_reputation', True)
        verbose = options.get('verbose', True) # Paksa True untuk logging backend

        job['status'] = 'processing'
        job['started_at'] = datetime.now().isoformat()

    thread = threading.Thread(
        target=analyze_pcap_background,
        args=(job_id, rules_dir, enable_reputation, verbose)
    )
    thread.daemon = True
    thread.start()

    return jsonify({'job_id': job_id, 'status': 'processing'}), 202

# =========================================================
# FIX 3: Background Task dengan File Logging (analysis.log)
# =========================================================
def analyze_pcap_background(job_id, rules_dir, enable_reputation, verbose):
    output_dir = storage.create_output_dir(job_id)
    log_file_path = os.path.join(output_dir, "analysis.log")

    def add_log(message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        with jobs_lock:
            if job_id in jobs:
                jobs[job_id]['logs'].append(entry)
        try:
            with open(log_file_path, "a") as f:
                f.write(entry + "\n")
        except: pass

    try:
        with jobs_lock:
            job = jobs[job_id]
            filepath = job['filepath']
            abuseipdb_key = job.get('abuseipdb_key')

        add_log("--- Memulai Sesi Analisis ---")
        add_log(f"Menggunakan rules: {rules_dir}")

        analyzer = PCAPAnalyzer(
            rules_dir=rules_dir,
            abuseipdb_key=abuseipdb_key if enable_reputation else None,
            verbose=verbose
        )

        def progress_cb(current, total, status):
            with jobs_lock:
                if job_id in jobs:
                    jobs[job_id]['progress'] = int((current / total) * 100) if total > 0 else 0
                    jobs[job_id]['status_message'] = status
            add_log(f"Progress: {status}")

        results = analyzer.analyze(
            pcap_file=filepath,
            output_dir=output_dir,
            progress_callback=progress_cb
        )

        with jobs_lock:
            if job_id in jobs:
                jobs[job_id].update({
                    'status': 'completed',
                    'completed_at': datetime.now().isoformat(),
                    'progress': 100,
                    'results': results,
                    'output_dir': output_dir
                })
        add_log("✅ Analisis Selesai.")

    except Exception as e:
        with jobs_lock:
            if job_id in jobs:
                jobs[job_id].update({
                    'status': 'failed',
                    'error': str(e),
                    'failed_at': datetime.now().isoformat()
                })
        add_log(f"🚨 ERROR: {str(e)}")

@app.route('/api/status/<job_id>', methods=['GET'])
def get_status(job_id):
    with jobs_lock:
        if job_id not in jobs:
            return jsonify({'error': 'Job not found'}), 404
        job = jobs[job_id].copy()

    # Keamanan data sensitif
    if 'abuseipdb_key' in job: job['abuseipdb_key'] = '***' if job['abuseipdb_key'] else None
    if 'filepath' in job: del job['filepath']

    return jsonify(job)

@app.route('/api/results/<job_id>', methods=['GET'])
def get_results(job_id):
    with jobs_lock:
        if job_id not in jobs or jobs[job_id]['status'] != 'completed':
            return jsonify({'error': 'Results not ready'}), 400
        job = jobs[job_id]

    output_dir = job.get('output_dir')
    files = os.listdir(output_dir) if output_dir and os.path.exists(output_dir) else []

    return jsonify({
        'job_id': job_id,
        'status': 'completed',
        'results': job['results'],
        'files': files,
        'logs': job.get('logs', [])
    })

@app.route('/api/download/<job_id>/<filename>', methods=['GET'])
def download_file(job_id, filename):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job or not job.get('output_dir'):
        return jsonify({'error': 'Not found'}), 404

    filepath = os.path.join(job['output_dir'], secure_filename(filename))
    return send_file(filepath, as_attachment=True)

@app.route('/api/jobs', methods=['GET'])
def list_jobs():
    with jobs_lock:
        # Sort by created_at desc, pastikan data tidak None
        sorted_jobs = sorted(
            jobs.values(),
            key=lambda x: x.get('created_at', ''),
            reverse=True
        )
        return jsonify({
            'jobs': sorted_jobs[:50],
            'total': len(jobs)
        })

@app.route('/api/upload_rules', methods=['POST'])
def upload_rules():
    try:
        files = request.files.getlist('files')
        upload_id = str(uuid.uuid4())[:8]
        target_dir = os.path.join(project_home, 'rules', 'uploads', upload_id)
        os.makedirs(target_dir, exist_ok=True)

        saved = []
        for file in files:
            if file and (file.filename.endswith('.yaml') or file.filename.endswith('.yml')):
                fname = secure_filename(file.filename)
                file.save(os.path.join(target_dir, fname))
                saved.append(fname)

        return jsonify({'rules_path': target_dir, 'files_count': len(saved)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)
    app.run(host='0.0.0.0', port=5000)
