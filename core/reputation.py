import requests
import time
import sqlite3
import ipaddress
import os
from datetime import datetime

class ReputationChecker:
    def __init__(self, api_key=None, use_api=False, db_path="data/threat_intel.db", enable_cache=True, verbose=False):
        self.api_key = api_key
        self.use_api = use_api
        self.db_path = db_path
        self.base_url = "https://api.abuseipdb.com/api/v2/check"
        self.verbose = verbose
        self.enabled = True 
        
        self.enable_cache = enable_cache
        self.cache = {}
        self.cache_ttl = 3600 
        
        self.total_checks = 0
        self.cache_hits = 0
        self.api_calls = 0
        self.malicious_ips_found = 0
        
        self.last_call_time = 0
        self.min_call_interval = 1.0 

    def check_ip(self, ip_address, max_age_days=90):
        """Alur: Cache -> Database Server (SQLite) -> API (Jika --use-api aktif)"""
        if not ip_address or self._is_private_ip(ip_address):
            return None
        
        self.total_checks += 1
        
        # 1. Cek Cache Memori
        if self.enable_cache and ip_address in self.cache:
            cache_entry = self.cache[ip_address]
            if (time.time() - cache_entry['timestamp']) < self.cache_ttl:
                self.cache_hits += 1
                return cache_entry['data']

        # 2. Langkah Pertama: Cek Database Server (Offline)
        local_match = self._check_local_blacklist(ip_address)
        
        if local_match:
            geo = self._get_geo_info(ip_address)
            result = {
                'ip': ip_address,
                'is_malicious': True,
                'abuse_confidence_score': 100,
                'country_code': geo.get('countryCode', '??'),
                'isp': geo.get('isp', f"Listed in {local_match}"),
                'source': f'Local Server DB ({local_match})',
                'cached': False
            }
            self._update_cache(ip_address, result)
            self.malicious_ips_found += 1
            return result

        # 3. Langkah Kedua: Cek API AbuseIPDB (Jika diminta user)
        if self.use_api and self.api_key:
            self._rate_limit()
            result = self._call_abuse_api(ip_address, max_age_days)
            if result:
                self._update_cache(ip_address, result)
                if result['is_malicious']:
                    self.malicious_ips_found += 1
                return result

        return None

    def _check_local_blacklist(self, ip_addr):
        """Mencocokkan IP dengan ribuan data di database Server."""
        if not os.path.exists(self.db_path):
            return None
        
        try:
            target_ip = ipaddress.ip_address(ip_addr)
            # Pastikan database ada di folder 'data' di sisi server
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT ip_address, source FROM local_blacklist")
            rows = cursor.fetchall()
            conn.close()

            for subnet_str, source in rows:
                # Cek apakah IP sesuai dengan entri (mendukung IP tunggal & CIDR)
                if target_ip in ipaddress.ip_network(subnet_str, strict=False):
                    return source
        except Exception as e:
            if self.verbose: print(f"[Reputation] DB Error: {e}")
        return None

    def _get_geo_info(self, ip):
        """Pengayaan data lokasi gratis via API publik"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return {}

    def _call_abuse_api(self, ip_address, max_age_days):
        try:
            headers = {'Key': self.api_key, 'Accept': 'application/json'}
            params = {'ipAddress': ip_address, 'maxAgeInDays': max_age_days}
            response = requests.get(self.base_url, headers=headers, params=params, timeout=10)
            self.api_calls += 1
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    'ip': ip_address,
                    'is_malicious': data['abuseConfidenceScore'] > 50,
                    'abuse_confidence_score': data['abuseConfidenceScore'],
                    'country_code': data.get('countryCode', '??'),
                    'isp': data.get('isp', 'Unknown ISP'),
                    'source': 'AbuseIPDB API',
                    'cached': False
                }
        except:
            pass
        return None

    def _update_cache(self, ip, data):
        if self.enable_cache:
            self.cache[ip] = {'data': data, 'timestamp': time.time()}

    def _is_private_ip(self, ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return True

    def _rate_limit(self):
        current_time = time.time()
        elapsed = current_time - self.last_call_time
        if elapsed < self.min_call_interval:
            time.sleep(self.min_call_interval - elapsed)
        self.last_call_time = time.time()

    def get_statistics(self):
        return {
            'total_checks': self.total_checks,
            'cache_hits': self.cache_hits,
            'api_calls': self.api_calls,
            'malicious_ips_found': self.malicious_ips_found
        }