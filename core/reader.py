"""
Packet Reader Module
Handles reading PCAP/PCAPNG files using Scapy with streaming support
"""

from scapy.all import PcapReader, rdpcap
from scapy.error import Scapy_Exception
import os
import struct  

class PacketReader:
    """
    Class for reading network capture files efficiently
    Uses streaming to avoid loading entire file into memory
    """
    
    def __init__(self, pcap_file):
        """
        Initialize packet reader
        
        Args:
            pcap_file (str): Path to PCAP/PCAPNG file
        
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file is invalid or corrupted
        """
        self.pcap_file = pcap_file
        self.validate_file()
    
    def validate_file(self):
        """Validate PCAP file exists and is readable"""
        if not os.path.exists(self.pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
        
        if not os.path.isfile(self.pcap_file):
            raise ValueError(f"Path is not a file: {self.pcap_file}")
        
        if os.path.getsize(self.pcap_file) == 0:
            raise ValueError(f"PCAP file is empty: {self.pcap_file}")
        
        # Try to read first packet to validate format
        try:
            test_reader = PcapReader(self.pcap_file)
            test_packet = test_reader.read_packet()
            test_reader.close()
            if test_packet is None:
                raise ValueError("No valid packets found in PCAP file")
        except (Scapy_Exception, struct.error) as e:
            raise ValueError(f"Invalid or corrupted PCAP file: {str(e)}")
    
    def read_packets(self):
        """
        Generator function to read packets one by one (streaming)
        This avoids loading entire capture into memory
        
        Yields:
            scapy.packet.Packet: Individual packet from capture
        """
        try:
            with PcapReader(self.pcap_file) as pcap_reader:
                for packet in pcap_reader:
                    yield packet
        except Scapy_Exception as e:
            raise ValueError(f"Error reading PCAP file: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error while reading packets: {str(e)}")
    
    def count_packets(self):
        """
        Count total packets in file (warning: reads entire file)
        
        Returns:
            int: Total number of packets
        """
        count = 0
        for _ in self.read_packets():
            count += 1
        return count
    
    def get_file_info(self):
        """
        Get basic information about the capture file
        
        Returns:
            dict: File information including size and path
        """
        return {
            'path': self.pcap_file,
            'size_bytes': os.path.getsize(self.pcap_file),
            'size_mb': round(os.path.getsize(self.pcap_file) / (1024 * 1024), 2),
            'exists': os.path.exists(self.pcap_file)
        }
