"""
PCAP Analyzer Engine
Core analysis logic for server
"""

import sys
import os

# Menambahkan parent directory ke path untuk import modul core
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.reader import PacketReader
from core.parser import PacketParser
from core.engine import RuleEngine
from core.writer import LogWriter
from core.reputation import ReputationChecker


class PCAPAnalyzer:
    """
    Main analyzer class for processing PCAP files
    """

    def __init__(self, rules_dir='rules', abuseipdb_key=None, use_api=False, verbose=False):
        self.rules_dir = rules_dir
        self.abuseipdb_key = abuseipdb_key
        self.use_api = use_api
        self.verbose = verbose

        self.parser = PacketParser(verbose=verbose)
        self.engine = RuleEngine(rules_dir)

        # ReputationChecker untuk Database Lokal & API Hybrid
        self.reputation = ReputationChecker(
            api_key=abuseipdb_key,
            use_api=use_api,
            enable_cache=True,
            verbose=verbose
        )

    def analyze(self, pcap_file, output_dir, progress_callback=None):
        """
        Melakukan analisis file PCAP dengan proteksi terhadap nilai None.
        """
        reader = PacketReader(pcap_file)
        writer = LogWriter(output_dir)

        stats = {
            'total_packets': 0,
            'parsed_packets': 0,
            'alerts': 0,
            'rules_matched': {},
            'protocols': {},
            'malicious_ips': {},
            'checked_ips': set(),
            'unique_src_ips': set(),
            'unique_dst_ips': set(),
        }

        for packet in reader.read_packets():
            stats['total_packets'] += 1

            # Parsing paket
            parsed = self.parser.parse(packet)
            if not parsed:
                continue

            stats['parsed_packets'] += 1

            # --- PERBAIKAN 1: Proteksi Protokol (Cegah NoneType Error) ---
            # Menggunakan 'or' memastikan variabel tidak akan bernilai None
            protocol = parsed.get('protocol') or 'Unknown'
            stats['protocols'][protocol] = stats['protocols'].get(protocol, 0) + 1

            # --- PERBAIKAN 2: Proteksi IP Tracking ---
            src_ip = parsed.get('src_ip')
            dst_ip = parsed.get('dst_ip')

            if src_ip:
                stats['unique_src_ips'].add(src_ip)
            if dst_ip:
                stats['unique_dst_ips'].add(dst_ip)

            # --- PERBAIKAN 3: Proteksi Reputasi IP ---
            if self.reputation and self.reputation.enabled:
                # Hanya cek IP yang valid (tidak None)
                for ip_addr in [src_ip, dst_ip]:
                    if ip_addr and ip_addr not in stats['checked_ips']:
                        stats['checked_ips'].add(ip_addr)

                        rep_data = self.reputation.check_ip(ip_addr)
                        if rep_data and rep_data.get('is_malicious'):
                            stats['malicious_ips'][ip_addr] = rep_data
                            writer.write_reputation_alert(parsed, rep_data, 'src_ip' if ip_addr == src_ip else 'dst_ip')
                            stats['alerts'] += 1

            # Cek Rules
            matched_rules = []
            if self.engine.rule_count > 0:
                matched_rules = self.engine.check_packet(parsed, packet)

            writer.write_connection(parsed)

            if matched_rules:
                stats['alerts'] += len(matched_rules)
                for rule in matched_rules:
                    writer.write_alert(parsed, rule)
                    rule_name = rule.get('name') or 'Unknown'
                    stats['rules_matched'][rule_name] = stats['rules_matched'].get(rule_name, 0) + 1

            # Logs spesifik protokol
            if protocol == 'DNS':
                writer.write_dns(parsed)
            elif protocol == 'HTTP':
                writer.write_http(parsed)

            if progress_callback and stats['total_packets'] % 100 == 0:
                progress_callback(
                    stats['total_packets'],
                    stats['total_packets'],
                    f"Analyzing packets... {stats['total_packets']} processed"
                )

        writer.close_all()

        # Statistik Reputasi
        reputation_stats = self.reputation.get_statistics() if self.reputation else None

        # Menyusun Hasil Akhir
        results = {
            'total_packets': stats['total_packets'],
            'parsed_packets': stats['parsed_packets'],
            'alerts_generated': stats['alerts'],
            'rules_applied': self.engine.rule_count,
            'unique_source_ips': len(stats['unique_src_ips']),
            'unique_destination_ips': len(stats['unique_dst_ips']),
            'protocols': stats['protocols'],
            'top_rules_matched': dict(sorted(
                stats['rules_matched'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'malicious_ips_found': len(stats['malicious_ips']),
            'malicious_ip_details': {
                ip: {
                    'score': data.get('abuse_confidence_score', 0),
                    'country': data.get('country_code', '??'),
                    'isp': data.get('isp', 'Unknown')
                }
                for ip, data in list(stats['malicious_ips'].items())[:10]
            },
            'reputation_checking': reputation_stats
        }

        return results
