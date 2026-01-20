#!/usr/bin/env python3
"""
Network Analyzer Server - REST API
Flask-based server untuk processing PCAP files
"""

from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
import os
import threading
import uuid
import time
from datetime import datetime
import json
import uuid
from analyzer import PCAPAnalyzer
from storage import StorageManager

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
app.json.sort_keys = False
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['OUTPUT_FOLDER'] = os.path.join(BASE_DIR, 'outputs')

# Initialize storage manager
storage = StorageManager(
    upload_dir=app.config['UPLOAD_FOLDER'],
    output_dir=app.config['OUTPUT_FOLDER']
)

# Job tracking
jobs = {}
jobs_lock = threading.Lock()


def allowed_file(filename):
    """Check if file extension is allowed"""
    ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Network Analyzer Server',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/upload', methods=['POST'])
def upload_pcap():
    """
    Upload PCAP file to server

    Request: multipart/form-data
        - file: PCAP file
        - abuseipdb_key (optional): API key for reputation checking

    Response:
        {
            "job_id": "uuid",
            "filename": "capture.pcap",
            "size": 1234567,
            "status": "uploaded"
        }
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Allowed: .pcap, .pcapng, .cap'}), 400

    # Generate job ID
    job_id = str(uuid.uuid4())

    # Secure filename
    filename = secure_filename(file.filename)

    # Save file
    filepath = storage.save_upload(job_id, file, filename)
    file_size = os.path.getsize(filepath)

    # Get optional parameters
    abuseipdb_key = request.form.get('abuseipdb_key', None)

    # Create job record
    with jobs_lock:
        jobs[job_id] = {
            'job_id': job_id,
            'filename': filename,
            'filepath': filepath,
            'size': file_size,
            'status': 'uploaded',
            'created_at': datetime.now().isoformat(),
            'abuseipdb_key': abuseipdb_key,
            'progress': 0,
            'results': None,
            'error': None
        }

    return jsonify({
        'job_id': job_id,
        'filename': filename,
        'size': file_size,
        'status': 'uploaded',
        'message': 'File uploaded successfully. Use /api/analyze to start analysis.'
    }), 201


@app.route('/api/analyze/<job_id>', methods=['POST'])
def start_analysis(job_id):
    """
    Start analysis for uploaded PCAP

    Request Body (JSON):
        {
            "rules_dir": "rules/",  # optional
            "enable_reputation": true,  # optional
            "verbose": false  # optional
        }

    Response:
        {
            "job_id": "uuid",
            "status": "processing",
            "message": "Analysis started"
        }
    """
    with jobs_lock:
        if job_id not in jobs:
            return jsonify({'error': 'Job not found'}), 404

        job = jobs[job_id]

        if job['status'] != 'uploaded':
            return jsonify({
                'error': f'Job already {job["status"]}',
                'current_status': job['status']
            }), 400

        # Get analysis options
        options = request.get_json() or {}
        rules_dir = options.get('rules_dir', 'rules')
        enable_reputation = options.get('enable_reputation', True)
        verbose = options.get('verbose', False)

        # Update job status
        job['status'] = 'processing'
        job['started_at'] = datetime.now().isoformat()
        job['options'] = options

    # Start analysis in background thread
    thread = threading.Thread(
        target=analyze_pcap_background,
        args=(job_id, rules_dir, enable_reputation, verbose)
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        'job_id': job_id,
        'status': 'processing',
        'message': 'Analysis started. Use /api/status/{job_id} to check progress.'
    }), 202


def analyze_pcap_background(job_id, rules_dir, enable_reputation, verbose):
    """Background task for PCAP analysis"""
    try:
        with jobs_lock:
            job = jobs[job_id]
            filepath = job['filepath']
            abuseipdb_key = job.get('abuseipdb_key')

        # Create analyzer
        analyzer = PCAPAnalyzer(
            rules_dir=rules_dir,
            abuseipdb_key=abuseipdb_key if enable_reputation else None,
            verbose=verbose
        )

        # Create output directory for this job
        output_dir = storage.create_output_dir(job_id)

        # Run analysis with progress callback
        def progress_callback(current, total, status):
            with jobs_lock:
                jobs[job_id]['progress'] = int((current / total) * 100) if total > 0 else 0
                jobs[job_id]['status_message'] = status

        results = analyzer.analyze(
            pcap_file=filepath,
            output_dir=output_dir,
            progress_callback=progress_callback
        )

        # Update job with results
        with jobs_lock:
            jobs[job_id]['status'] = 'completed'
            jobs[job_id]['completed_at'] = datetime.now().isoformat()
            jobs[job_id]['progress'] = 100
            jobs[job_id]['results'] = results
            jobs[job_id]['output_dir'] = output_dir

    except Exception as e:
        # Handle errors
        with jobs_lock:
            jobs[job_id]['status'] = 'failed'
            jobs[job_id]['error'] = str(e)
            jobs[job_id]['failed_at'] = datetime.now().isoformat()


@app.route('/api/status/<job_id>', methods=['GET'])
def get_status(job_id):
    """
    Get job status and progress

    Response:
        {
            "job_id": "uuid",
            "status": "processing|completed|failed",
            "progress": 75,
            "results": {...}  # if completed
        }
    """
    with jobs_lock:
        if job_id not in jobs:
            return jsonify({'error': 'Job not found'}), 404

        job = jobs[job_id].copy()

    # Remove sensitive data
    if 'abuseipdb_key' in job:
        job['abuseipdb_key'] = '***' if job['abuseipdb_key'] else None

    if 'filepath' in job:
        del job['filepath']

    return jsonify(job)


@app.route('/api/results/<job_id>', methods=['GET'])
def get_results(job_id):
    """
    Get analysis results

    Response:
        {
            "job_id": "uuid",
            "results": {
                "total_packets": 1000,
                "alerts": 50,
                "malicious_ips": 5,
                ...
            },
            "files": ["conn.log", "alert.log", ...]
        }
    """
    with jobs_lock:
        if job_id not in jobs:
            return jsonify({'error': 'Job not found'}), 404

        job = jobs[job_id]

        if job['status'] != 'completed':
            return jsonify({
                'error': 'Analysis not completed',
                'status': job['status']
            }), 400

    # Get list of output files
    output_dir = job.get('output_dir')
    files = []
    if output_dir and os.path.exists(output_dir):
        files = os.listdir(output_dir)

    return jsonify({
        'job_id': job_id,
        'status': 'completed',
        'results': job['results'],
        'files': files,
        'output_directory': output_dir
    })


@app.route('/api/download/<job_id>/<filename>', methods=['GET'])
def download_file(job_id, filename):
    """
    Download specific log file

    Example: GET /api/download/{job_id}/alert.log
    """
    with jobs_lock:
        if job_id not in jobs:
            return jsonify({'error': 'Job not found'}), 404

        job = jobs[job_id]

        if job['status'] != 'completed':
            return jsonify({'error': 'Analysis not completed'}), 400

        output_dir = job.get('output_dir')

    if not output_dir:
        return jsonify({'error': 'Output directory not found'}), 404

    # Secure filename
    filename = secure_filename(filename)
    filepath = os.path.join(output_dir, filename)

    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404

    return send_file(filepath, as_attachment=True)


@app.route('/api/jobs', methods=['GET'])
def list_jobs():
    """
    List all jobs

    Query params:
        - status: filter by status (uploaded|processing|completed|failed)
        - limit: max number of results (default: 50)

    Response:
        {
            "jobs": [...],
            "total": 10
        }
    """
    status_filter = request.args.get('status')
    limit = int(request.args.get('limit', 50))

    with jobs_lock:
        job_list = list(jobs.values())

    # Filter by status
    if status_filter:
        job_list = [j for j in job_list if j['status'] == status_filter]

    # Sort by created_at (newest first)
    job_list.sort(key=lambda x: x['created_at'], reverse=True)

    # Limit results
    job_list = job_list[:limit]

    # Remove sensitive data
    for job in job_list:
        if 'abuseipdb_key' in job:
            job['abuseipdb_key'] = '***' if job['abuseipdb_key'] else None
        if 'filepath' in job:
            del job['filepath']

    return jsonify({
        'jobs': job_list,
        'total': len(job_list)
    })


@app.route('/api/delete/<job_id>', methods=['DELETE'])
def delete_job(job_id):
    """
    Delete job and associated files

    Response:
        {
            "message": "Job deleted successfully"
        }
    """
    with jobs_lock:
        if job_id not in jobs:
            return jsonify({'error': 'Job not found'}), 404

        job = jobs[job_id]

    # Delete files
    storage.delete_job(job_id, job)

    # Remove from jobs dict
    with jobs_lock:
        del jobs[job_id]

    return jsonify({
        'message': 'Job deleted successfully',
        'job_id': job_id
    })

@app.route('/api/upload_rules', methods=['POST'])
def upload_rules():
    """
    Endpoint untuk menerima custom rules (.yaml) dari client
    Disimpan di folder: rules/uploads/<unique_id>/
    """
    try:
        if 'files' not in request.files:
            return jsonify({'error': 'No files provided'}), 400

        files = request.files.getlist('files')
        if not files or files[0].filename == '':
            return jsonify({'error': 'No selected files'}), 400

        # 1. Buat folder unik untuk sesi upload ini
        upload_id = str(uuid.uuid4())[:8]  # Contoh: a1b2c3d4
        # Path relatif terhadap root project
        target_dir = os.path.join('rules', 'uploads', upload_id)

        # Buat folder fisik
        os.makedirs(target_dir, exist_ok=True)

        saved_files = []
        for file in files:
            if file and (file.filename.endswith('.yaml') or file.filename.endswith('.yml')):
                filename = secure_filename(file.filename)
                file_path = os.path.join(target_dir, filename)
                file.save(file_path)
                saved_files.append(filename)

        if not saved_files:
            return jsonify({'error': 'No valid YAML files found'}), 400

        return jsonify({
            'message': 'Rules uploaded successfully',
            'upload_id': upload_id,
            'rules_path': target_dir,  # Path ini yang nanti dipakai analyzer
            'files_count': len(saved_files)
        })

    except Exception as e:
        print(f"Error uploading rules: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Create directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

    # Run server
    print("=" * 60)
    print("Network Analyzer Server")
    print("=" * 60)
    print(f"Server running at: http://0.0.0.0:5000")
    print(f"API Documentation: http://0.0.0.0:5000/api/health")
    print("=" * 60)

    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
