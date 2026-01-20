"""
Packet Parser Module
Extracts information from network packets including IP, Port, Protocol, and Payload
"""

from scapy.all import IP, IPv6, TCP, UDP, DNS, Raw, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse
from datetime import datetime


class PacketParser:
    """
    Class for parsing network packets and extracting relevant information
    """
    
    def __init__(self, verbose=False):
        """
        Initialize packet parser
        
        Args:
            verbose (bool): Enable verbose output
        """
        self.verbose = verbose
    
    def parse(self, packet):
        """
        Parse a packet and extract all relevant information
        
        Args:
            packet: Scapy packet object
        
        Returns:
            dict: Parsed packet information or None if not parseable
        """
        try:
            parsed_data = {
                'timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'protocol': None,
                'length': len(packet),
                'payload': None,
                'payload_size': 0,
                'flags': None,
                'extra': {}
            }
            
            # Extract IP information
            if IP in packet:
                parsed_data['src_ip'] = packet[IP].src
                parsed_data['dst_ip'] = packet[IP].dst
                parsed_data['protocol'] = self._get_protocol_name(packet[IP].proto)
            elif IPv6 in packet:
                parsed_data['src_ip'] = packet[IPv6].src
                parsed_data['dst_ip'] = packet[IPv6].dst
                parsed_data['protocol'] = 'IPv6'
            
            # Extract TCP information
            if TCP in packet:
                parsed_data['src_port'] = packet[TCP].sport
                parsed_data['dst_port'] = packet[TCP].dport
                parsed_data['protocol'] = 'TCP'
                parsed_data['flags'] = self._get_tcp_flags(packet[TCP].flags)
            
            # Extract UDP information
            elif UDP in packet:
                parsed_data['src_port'] = packet[UDP].sport
                parsed_data['dst_port'] = packet[UDP].dport
                parsed_data['protocol'] = 'UDP'
            
            # Extract DNS information
            if DNS in packet:
                parsed_data['protocol'] = 'DNS'
                dns_info = self._parse_dns(packet[DNS])
                parsed_data['extra']['dns'] = dns_info
            
            # Extract HTTP information
            if HTTPRequest in packet:
                parsed_data['protocol'] = 'HTTP'
                http_info = self._parse_http_request(packet[HTTPRequest])
                parsed_data['extra']['http'] = http_info
            elif HTTPResponse in packet:
                parsed_data['protocol'] = 'HTTP'
                http_info = self._parse_http_response(packet[HTTPResponse])
                parsed_data['extra']['http'] = http_info
            
            # Extract payload
            if Raw in packet:
                payload_bytes = bytes(packet[Raw].load)
                parsed_data['payload'] = payload_bytes
                parsed_data['payload_size'] = len(payload_bytes)
                
                # Try to decode as text
                try:
                    parsed_data['payload_text'] = payload_bytes.decode('utf-8', errors='ignore')
                except:
                    parsed_data['payload_text'] = None
            
            return parsed_data
            
        except Exception as e:
            if self.verbose:
                print(f"Warning: Failed to parse packet - {str(e)}")
            return None
    
    def _get_protocol_name(self, proto_num):
        """Convert protocol number to name"""
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            58: 'ICMPv6'
        }
        return protocols.get(proto_num, f'Protocol-{proto_num}')
    
    def _get_tcp_flags(self, flags):
        """Extract TCP flags as string"""
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        return ','.join(flag_names) if flag_names else 'NONE'
    
    def _parse_dns(self, dns_layer):
        """Parse DNS packet"""
        dns_info = {
            'query': None,
            'response': [],
            'type': 'query' if dns_layer.qr == 0 else 'response'
        }
        
        # Extract query
        if DNSQR in dns_layer:
            dns_info['query'] = dns_layer[DNSQR].qname.decode('utf-8', errors='ignore')
            dns_info['qtype'] = dns_layer[DNSQR].qtype
        
        # Extract responses
        if DNSRR in dns_layer:
            answer_count = dns_layer.ancount
            for i in range(answer_count):
                try:
                    rr = dns_layer.an[i]
                    dns_info['response'].append({
                        'name': rr.rrname.decode('utf-8', errors='ignore'),
                        'data': rr.rdata if isinstance(rr.rdata, str) else str(rr.rdata)
                    })
                except:
                    pass
        
        return dns_info
    
    def _parse_http_request(self, http_layer):
        """Parse HTTP request"""
        return {
            'method': http_layer.Method.decode() if http_layer.Method else None,
            'host': http_layer.Host.decode() if http_layer.Host else None,
            'path': http_layer.Path.decode() if http_layer.Path else None,
            'user_agent': http_layer.User_Agent.decode() if hasattr(http_layer, 'User_Agent') else None
        }
    
    def _parse_http_response(self, http_layer):
        """Parse HTTP response"""
        return {
            'status_code': http_layer.Status_Code.decode() if http_layer.Status_Code else None,
            'reason': http_layer.Reason_Phrase.decode() if http_layer.Reason_Phrase else None
        }
