"""
Storage Manager
Handles file storage for uploads and outputs
"""

import os
import shutil


class StorageManager:
    """
    Manages file storage for PCAP analyzer server
    """
    
    def __init__(self, upload_dir='uploads', output_dir='outputs'):
        """
        Initialize storage manager
        
        Args:
            upload_dir (str): Directory for uploaded files
            output_dir (str): Directory for analysis outputs
        """
        self.upload_dir = upload_dir
        self.output_dir = output_dir
        
        # Create directories
        os.makedirs(upload_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)
    
    def save_upload(self, job_id, file, original_filename):
        """
        Save uploaded file
        
        Args:
            job_id (str): Job ID
            file: FileStorage object from Flask
            original_filename (str): Original filename
        
        Returns:
            str: Path to saved file
        """
        # Create job directory
        job_dir = os.path.join(self.upload_dir, job_id)
        os.makedirs(job_dir, exist_ok=True)
        
        # Save file
        filepath = os.path.join(job_dir, original_filename)
        file.save(filepath)
        
        return filepath
    
    def create_output_dir(self, job_id):
        """
        Create output directory for job
        
        Args:
            job_id (str): Job ID
        
        Returns:
            str: Path to output directory
        """
        output_path = os.path.join(self.output_dir, job_id)
        os.makedirs(output_path, exist_ok=True)
        return output_path
    
    def delete_job(self, job_id, job_data):
        """
        Delete all files associated with a job
        
        Args:
            job_id (str): Job ID
            job_data (dict): Job data containing file paths
        """
        # Delete upload directory
        upload_path = os.path.join(self.upload_dir, job_id)
        if os.path.exists(upload_path):
            shutil.rmtree(upload_path)
        
        # Delete output directory
        output_path = os.path.join(self.output_dir, job_id)
        if os.path.exists(output_path):
            shutil.rmtree(output_path)
    
    def get_job_size(self, job_id):
        """
        Get total size of job files
        
        Args:
            job_id (str): Job ID
        
        Returns:
            int: Total size in bytes
        """
        total_size = 0
        
        # Upload directory
        upload_path = os.path.join(self.upload_dir, job_id)
        if os.path.exists(upload_path):
            for dirpath, dirnames, filenames in os.walk(upload_path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    total_size += os.path.getsize(filepath)
        
        # Output directory
        output_path = os.path.join(self.output_dir, job_id)
        if os.path.exists(output_path):
            for dirpath, dirnames, filenames in os.walk(output_path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    total_size += os.path.getsize(filepath)
        
        return total_size