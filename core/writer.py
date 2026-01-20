"""
Log Writer Module
Handles writing various log files (conn.log, alert.log, dns.log, http.log)
"""

import os
import json
from datetime import datetime


class LogWriter:
    """
    Class for writing packet analysis results to log files
    """
    
    def __init__(self, output_dir):
        """
        Initialize log writer
        
        Args:
            output_dir (str): Directory to write log files
        """
        self.output_dir = output_dir
        self.log_files = {}
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize log files
        self._init_log_files()
    
    def _init_log_files(self):
        """Initialize all log files with headers"""
        log_configs = {
            'conn': 'conn.log',
            'alert': 'alert.log',
            'dns': 'dns.log',
            'http': 'http.log',
            'reputation': 'reputation.log'  # NEW: Reputation log
        }
        
        for log_type, filename in log_configs.items():
            filepath = os.path.join(self.output_dir, filename)
            self.log_files[log_type] = open(filepath, 'w')
            
            # Write headers
            if log_type == 'conn':
                self._write_conn_header()
            elif log_type == 'alert':
                self._write_alert_header()
            elif log_type == 'dns':
                self._write_dns_header()
            elif log_type == 'http':
                self._write_http_header()
            elif log_type == 'reputation':
                self._write_reputation_header()
    
    def _write_conn_header(self):
        """Write connection log header"""
        header = "timestamp\tsrc_ip\tsrc_port\tdst_ip\tdst_port\tprotocol\tflags\tlength\n"
        self.log_files['conn'].write(header)
    
    def _write_alert_header(self):
        """Write alert log header"""
        header = "timestamp\tsrc_ip\tsrc_port\tdst_ip\tdst_port\trule_name\tseverity\tdescription\n"
        self.log_files['alert'].write(header)
    
    def _write_dns_header(self):
        """Write DNS log header"""
        header = "timestamp\tsrc_ip\tdst_ip\tquery\tquery_type\tresponse\n"
        self.log_files['dns'].write(header)
    
    def _write_http_header(self):
        """Write HTTP log header"""
        header = "timestamp\tsrc_ip\tsrc_port\tdst_ip\tdst_port\tmethod\thost\tpath\tuser_agent\n"
        self.log_files['http'].write(header)
    
    def _write_reputation_header(self):
        """Write reputation log header"""
        header = "timestamp\tip\tip_type\tabuse_score\ttotal_reports\tcountry\tisp\tusage_type\tlast_reported\n"
        self.log_files['reputation'].write(header)
    
    def write_connection(self, parsed_packet):
        """
        Write connection information to conn.log
        
        Args:
            parsed_packet (dict): Parsed packet data
        """
        if not parsed_packet:
            return
        
        try:
            line = "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n".format(
                parsed_packet.get('timestamp', '-'),
                parsed_packet.get('src_ip', '-'),
                parsed_packet.get('src_port', '-'),
                parsed_packet.get('dst_ip', '-'),
                parsed_packet.get('dst_port', '-'),
                parsed_packet.get('protocol', '-'),
                parsed_packet.get('flags', '-'),
                parsed_packet.get('length', 0)
            )
            self.log_files['conn'].write(line)
            self.log_files['conn'].flush()
        except Exception as e:
            print(f"Error writing connection log: {e}")
    
    def write_alert(self, parsed_packet, rule):
        """
        Write alert to alert.log
        
        Args:
            parsed_packet (dict): Parsed packet data
            rule (dict): Matched rule
        """
        if not parsed_packet or not rule:
            return
        
        try:
            line = "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n".format(
                parsed_packet.get('timestamp', '-'),
                parsed_packet.get('src_ip', '-'),
                parsed_packet.get('src_port', '-'),
                parsed_packet.get('dst_ip', '-'),
                parsed_packet.get('dst_port', '-'),
                rule.get('name', 'Unknown'),
                rule.get('severity', 'medium'),
                rule.get('description', 'No description')
            )
            self.log_files['alert'].write(line)
            self.log_files['alert'].flush()
        except Exception as e:
            print(f"Error writing alert log: {e}")
    
    def write_dns(self, parsed_packet):
        """
        Write DNS information to dns.log
        
        Args:
            parsed_packet (dict): Parsed packet data
        """
        if not parsed_packet:
            return
        
        dns_data = parsed_packet.get('extra', {}).get('dns', {})
        if not dns_data:
            return
        
        try:
            response_str = json.dumps(dns_data.get('response', []))
            
            line = "{}\t{}\t{}\t{}\t{}\t{}\n".format(
                parsed_packet.get('timestamp', '-'),
                parsed_packet.get('src_ip', '-'),
                parsed_packet.get('dst_ip', '-'),
                dns_data.get('query', '-'),
                dns_data.get('qtype', '-'),
                response_str
            )
            self.log_files['dns'].write(line)
            self.log_files['dns'].flush()
        except Exception as e:
            print(f"Error writing DNS log: {e}")
    
    def write_http(self, parsed_packet):
        """
        Write HTTP information to http.log
        
        Args:
            parsed_packet (dict): Parsed packet data
        """
        if not parsed_packet:
            return
        
        http_data = parsed_packet.get('extra', {}).get('http', {})
        if not http_data:
            return
        
        try:
            line = "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n".format(
                parsed_packet.get('timestamp', '-'),
                parsed_packet.get('src_ip', '-'),
                parsed_packet.get('src_port', '-'),
                parsed_packet.get('dst_ip', '-'),
                parsed_packet.get('dst_port', '-'),
                http_data.get('method', '-'),
                http_data.get('host', '-'),
                http_data.get('path', '-'),
                http_data.get('user_agent', '-')
            )
            self.log_files['http'].write(line)
            self.log_files['http'].flush()
        except Exception as e:
            print(f"Error writing HTTP log: {e}")
    
    def write_reputation_alert(self, parsed_packet, reputation_data, ip_type):
        """
        Write IP reputation alert to reputation.log
        
        Args:
            parsed_packet (dict): Parsed packet data
            reputation_data (dict): Reputation data from AbuseIPDB
            ip_type (str): 'src_ip' or 'dst_ip'
        """
        if not parsed_packet or not reputation_data:
            return
        
        try:
            line = "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n".format(
                parsed_packet.get('timestamp', '-'),
                reputation_data.get('ip', '-'),
                ip_type,
                reputation_data.get('abuse_confidence_score', 0),
                reputation_data.get('total_reports', 0),
                reputation_data.get('country_code', '-'),
                reputation_data.get('isp', '-'),
                reputation_data.get('usage_type', '-'),
                reputation_data.get('last_reported', '-')
            )
            self.log_files['reputation'].write(line)
            self.log_files['reputation'].flush()
        except Exception as e:
            print(f"Error writing reputation log: {e}")
    
    def close_all(self):
        """Close all log files"""
        for log_file in self.log_files.values():
            try:
                log_file.close()
            except:
                pass
    
    def __del__(self):
        """Destructor to ensure files are closed"""
        self.close_all()
