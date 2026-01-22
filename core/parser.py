"""
Packet Parser Module - Hardened Version
Extracts information with robust null-safety and string searching capabilities.
"""

from scapy.all import IP, IPv6, TCP, UDP, DNS, Raw, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse
from datetime import datetime

class PacketParser:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def parse(self, packet):
        try:
            parsed_data = {
                'timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'protocol': 'Unknown', # Default string bukan None
                'length': len(packet),
                'payload': None,
                'payload_size': 0,
                'payload_text': "", # Inisialisasi string kosong
                'flags': None,
                'extra': {}
            }

            # --- 1. Robust IP Extraction ---
            if IP in packet:
                parsed_data['src_ip'] = packet[IP].src
                parsed_data['dst_ip'] = packet[IP].dst
                # Pastikan protocol selalu string UPPERCASE
                parsed_data['protocol'] = self._get_protocol_name(packet[IP].proto).upper()
            elif IPv6 in packet:
                parsed_data['src_ip'] = packet[IPv6].src
                parsed_data['dst_ip'] = packet[IPv6].dst
                parsed_data['protocol'] = 'IPV6'

            # --- 2. Port & TCP/UDP Safety ---
            if TCP in packet:
                parsed_data['src_port'] = packet[TCP].sport
                parsed_data['dst_port'] = packet[TCP].dport
                parsed_data['protocol'] = 'TCP'
                parsed_data['flags'] = self._get_tcp_flags(packet[TCP].flags)
            elif UDP in packet:
                parsed_data['src_port'] = packet[UDP].sport
                parsed_data['dst_port'] = packet[UDP].dport
                # Jika sebelumnya sudah diisi IP (misal UDP), tetap set ke UDP
                parsed_data['protocol'] = 'UDP'

            # --- 3. Application Layer Overrides ---
            if DNS in packet:
                parsed_data['protocol'] = 'DNS'
                parsed_data['extra']['dns'] = self._parse_dns(packet[DNS])

            if HTTPRequest in packet:
                parsed_data['protocol'] = 'HTTP'
                parsed_data['extra']['http'] = self._parse_http_request(packet[HTTPRequest])
            elif HTTPResponse in packet:
                parsed_data['protocol'] = 'HTTP'
                parsed_data['extra']['http'] = self._parse_http_response(packet[HTTPResponse])

            # --- 4. Payload Extraction & String Search Prep ---
            if Raw in packet:
                payload_bytes = bytes(packet[Raw].load)
                parsed_data['payload'] = payload_bytes
                parsed_data['payload_size'] = len(payload_bytes)

                # Decode payload untuk pencarian string (ignore errors agar tidak crash)
                parsed_data['payload_text'] = payload_bytes.decode('utf-8', errors='ignore')

            return parsed_data

        except Exception as e:
            if self.verbose:
                print(f"Warning: Failed to parse packet - {str(e)}")
            return None

    def _get_protocol_name(self, proto_num):
        """Convert protocol number to name with safety"""
        protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6'}
        return protocols.get(proto_num, f'PROTO-{proto_num}')

    def _get_tcp_flags(self, flags):
        """Extract TCP flags safely"""
        if flags is None: return 'NONE'
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        return ','.join(flag_names) if flag_names else 'NONE'

    def _parse_dns(self, dns_layer):
        dns_info = {'query': None, 'response': [], 'type': 'query' if dns_layer.qr == 0 else 'response'}
        if DNSQR in dns_layer and dns_layer[DNSQR].qname:
            dns_info['query'] = dns_layer[DNSQR].qname.decode('utf-8', errors='ignore')
        return dns_info

    def _parse_http_request(self, http_layer):
        """Robust HTTP parsing with None checking before decode"""
        return {
            'method': http_layer.Method.decode('utf-8', errors='ignore') if hasattr(http_layer, 'Method') and http_layer.Method else None,
            'host': http_layer.Host.decode('utf-8', errors='ignore') if hasattr(http_layer, 'Host') and http_layer.Host else None,
            'path': http_layer.Path.decode('utf-8', errors='ignore') if hasattr(http_layer, 'Path') and http_layer.Path else None
        }

    def _parse_http_response(self, http_layer):
        return {
            'status_code': http_layer.Status_Code.decode('utf-8', errors='ignore') if hasattr(http_layer, 'Status_Code') and http_layer.Status_Code else None
        }
