"""
Network Analyzer Client
REST API Client untuk berkomunikasi dengan server
"""

import requests
import time
import os
from typing import Optional, Dict, List


class NetworkAnalyzerClient:
    """
    Client untuk Network Analyzer Server
    """
    
    def __init__(self, server_url: str = "http://localhost:5000"):
        """
        Initialize client
        
        Args:
            server_url (str): Base URL of the server
        """
        self.server_url = server_url.rstrip('/')
        self.session = requests.Session()
    
    def health_check(self) -> Dict:
        """
        Check server health
        
        Returns:
            dict: Server health status
        """
        response = self.session.get(f"{self.server_url}/api/health")
        response.raise_for_status()
        return response.json()
    
    def upload_pcap(self, filepath: str, abuseipdb_key: Optional[str] = None) -> Dict:
        """
        Upload PCAP file to server
        
        Args:
            filepath (str): Path to PCAP file
            abuseipdb_key (str): Optional AbuseIPDB API key
        
        Returns:
            dict: Upload response with job_id
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        with open(filepath, 'rb') as f:
            files = {'file': (os.path.basename(filepath), f, 'application/octet-stream')}
            data = {}
            
            if abuseipdb_key:
                data['abuseipdb_key'] = abuseipdb_key
            
            response = self.session.post(
                f"{self.server_url}/api/upload",
                files=files,
                data=data,
                timeout=300  # 5 minutes timeout for large files
            )
            response.raise_for_status()
            return response.json()
    
    def start_analysis(self, job_id: str, 
                      rules_dir: str = "rules",
                      enable_reputation: bool = True,
                      verbose: bool = False) -> Dict:
        """
        Start analysis for uploaded PCAP
        
        Args:
            job_id (str): Job ID from upload
            rules_dir (str): Rules directory on server
            enable_reputation (bool): Enable IP reputation checking
            verbose (bool): Verbose output
        
        Returns:
            dict: Analysis start response
        """
        data = {
            'rules_dir': rules_dir,
            'enable_reputation': enable_reputation,
            'verbose': verbose
        }
        
        response = self.session.post(
            f"{self.server_url}/api/analyze/{job_id}",
            json=data
        )
        response.raise_for_status()
        return response.json()
    
    def get_status(self, job_id: str) -> Dict:
        """
        Get job status
        
        Args:
            job_id (str): Job ID
        
        Returns:
            dict: Job status
        """
        response = self.session.get(f"{self.server_url}/api/status/{job_id}")
        response.raise_for_status()
        return response.json()
    
    def wait_for_completion(self, job_id: str, 
                           poll_interval: int = 2,
                           timeout: int = 3600,
                           callback=None) -> Dict:
        """
        Wait for analysis to complete
        
        Args:
            job_id (str): Job ID
            poll_interval (int): Seconds between status checks
            timeout (int): Maximum wait time in seconds
            callback (function): Optional callback(status_dict)
        
        Returns:
            dict: Final job status
        """
        start_time = time.time()
        
        while True:
            # Check timeout
            if time.time() - start_time > timeout:
                raise TimeoutError(f"Analysis timeout after {timeout} seconds")
            
            # Get status
            status = self.get_status(job_id)
            
            # Call callback if provided
            if callback:
                callback(status)
            
            # Check if completed
            if status['status'] in ['completed', 'failed']:
                return status
            
            # Wait before next check
            time.sleep(poll_interval)
    
    def get_results(self, job_id: str) -> Dict:
        """
        Get analysis results
        
        Args:
            job_id (str): Job ID
        
        Returns:
            dict: Analysis results
        """
        response = self.session.get(f"{self.server_url}/api/results/{job_id}")
        response.raise_for_status()
        return response.json()
    
    def download_file(self, job_id: str, filename: str, output_path: str):
        """
        Download specific log file
        
        Args:
            job_id (str): Job ID
            filename (str): Filename to download
            output_path (str): Local path to save file
        """
        response = self.session.get(
            f"{self.server_url}/api/download/{job_id}/{filename}",
            stream=True
        )
        response.raise_for_status()
        
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
    
    def download_all_results(self, job_id: str, output_dir: str):
        """
        Download all result files
        
        Args:
            job_id (str): Job ID
            output_dir (str): Directory to save files
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # Get list of files
        results = self.get_results(job_id)
        files = results.get('files', [])
        
        # Download each file
        for filename in files:
            output_path = os.path.join(output_dir, filename)
            self.download_file(job_id, filename, output_path)
    
    def list_jobs(self, status: Optional[str] = None, limit: int = 50) -> Dict:
        """
        List all jobs
        
        Args:
            status (str): Filter by status
            limit (int): Max results
        
        Returns:
            dict: Jobs list
        """
        params = {'limit': limit}
        if status:
            params['status'] = status
        
        response = self.session.get(
            f"{self.server_url}/api/jobs",
            params=params
        )
        response.raise_for_status()
        return response.json()
    
    def delete_job(self, job_id: str) -> Dict:
        """
        Delete job and files
        
        Args:
            job_id (str): Job ID
        
        Returns:
            dict: Delete response
        """
        response = self.session.delete(f"{self.server_url}/api/delete/{job_id}")
        response.raise_for_status()
        return response.json()
    
    def analyze_pcap(self, filepath: str,
                    output_dir: str = "output",
                    abuseipdb_key: Optional[str] = None,
                    rules_dir: str = "rules",
                    enable_reputation: bool = True,
                    verbose: bool = False,
                    poll_interval: int = 2) -> Dict:
        """
        Complete workflow: upload, analyze, wait, download results
        
        Args:
            filepath (str): Path to PCAP file
            output_dir (str): Local output directory
            abuseipdb_key (str): AbuseIPDB API key
            rules_dir (str): Rules directory
            enable_reputation (bool): Enable reputation checking
            verbose (bool): Verbose output
            poll_interval (int): Status check interval
        
        Returns:
            dict: Analysis results
        """
        print(f"Uploading {filepath}...")
        upload_resp = self.upload_pcap(filepath, abuseipdb_key)
        job_id = upload_resp['job_id']
        print(f"✓ Uploaded. Job ID: {job_id}")
        
        print("Starting analysis...")
        self.start_analysis(job_id, rules_dir, enable_reputation, verbose)
        print("✓ Analysis started")
        
        print("Waiting for completion...")
        
        def progress_callback(status):
            progress = status.get('progress', 0)
            current_status = status.get('status', 'unknown')
            print(f"  Progress: {progress}% - Status: {current_status}")
        
        final_status = self.wait_for_completion(
            job_id,
            poll_interval=poll_interval,
            callback=progress_callback
        )
        
        if final_status['status'] == 'failed':
            error = final_status.get('error', 'Unknown error')
            raise Exception(f"Analysis failed: {error}")
        
        print("✓ Analysis completed")
        
        print(f"Downloading results to {output_dir}...")
        self.download_all_results(job_id, output_dir)
        print("✓ Results downloaded")
        
        results = self.get_results(job_id)
        return results