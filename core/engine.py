"""
Rule Engine Module
Loads and evaluates YAML rules against parsed packets
"""

import yaml
import os
import re
from pathlib import Path


class RuleEngine:
    """
    Rule engine for matching packets against YAML-defined rules
    """
    
    def __init__(self, rules_dir):
        """
        Initialize rule engine and load rules
        
        Args:
            rules_dir (str): Directory containing YAML rule files
        """
        self.rules_dir = rules_dir
        self.rules = []
        self.rule_count = 0
        self.load_rules()
    
    def load_rules(self):
        """Load all YAML rule files from rules directory"""
        if not os.path.isdir(self.rules_dir):
            # Silently skip if directory doesn't exist
            return
        
        yaml_files = list(Path(self.rules_dir).glob('*.yaml')) + \
                     list(Path(self.rules_dir).glob('*.yml'))
        
        if not yaml_files:
            # No rules found - this is okay, just continue without rules
            return
        
        for rule_file in yaml_files:
            try:
                with open(rule_file, 'r') as f:
                    rules_data = yaml.safe_load(f)
                    
                    if not rules_data:
                        continue
                    
                    # Handle both list of rules and single rule
                    if isinstance(rules_data, list):
                        for rule in rules_data:
                            self._validate_and_add_rule(rule, rule_file)
                    elif isinstance(rules_data, dict):
                        self._validate_and_add_rule(rules_data, rule_file)
                    
            except yaml.YAMLError as e:
                print(f"Error parsing YAML file {rule_file}: {e}")
            except Exception as e:
                print(f"Error loading rule file {rule_file}: {e}")
        
        self.rule_count = len(self.rules)
    
    def _validate_and_add_rule(self, rule, source_file):
        """Validate and add a rule to the engine"""
        required_fields = ['name', 'conditions']
        
        if not all(field in rule for field in required_fields):
            print(f"Warning: Invalid rule in {source_file} - missing required fields")
            return
        
        # Add metadata
        rule['source_file'] = str(source_file)
        rule['severity'] = rule.get('severity', 'medium')
        rule['enabled'] = rule.get('enabled', True)
        
        if rule['enabled']:
            self.rules.append(rule)
    
    def check_packet(self, parsed_packet, raw_packet=None):
        """
        Check if packet matches any rules
        
        Args:
            parsed_packet (dict): Parsed packet data
            raw_packet: Raw scapy packet (optional, for advanced checks)
        
        Returns:
            list: List of matched rules
        """
        matched_rules = []
        
        for rule in self.rules:
            if self._evaluate_rule(rule, parsed_packet, raw_packet):
                matched_rules.append(rule)
        
        return matched_rules
    
    def _evaluate_rule(self, rule, parsed_packet, raw_packet):
        """
        Evaluate a single rule against a packet
        
        Args:
            rule (dict): Rule definition
            parsed_packet (dict): Parsed packet data
            raw_packet: Raw packet
        
        Returns:
            bool: True if rule matches
        """
        conditions = rule.get('conditions', {})
        
        # Check each condition
        for condition_type, condition_value in conditions.items():
            if not self._check_condition(condition_type, condition_value, parsed_packet, raw_packet):
                return False
        
        return True
    
    def _check_condition(self, condition_type, condition_value, parsed_packet, raw_packet):
        """
        Check a specific condition
        
        Args:
            condition_type (str): Type of condition (port, protocol, ip, payload, etc.)
            condition_value: Value to check against
            parsed_packet (dict): Parsed packet data
            raw_packet: Raw packet
        
        Returns:
            bool: True if condition matches
        """
        # Protocol check
        if condition_type == 'protocol':
            return parsed_packet.get('protocol', '').upper() == str(condition_value).upper()
        
        # Source port check
        elif condition_type == 'src_port':
            return parsed_packet.get('src_port') == int(condition_value)
        
        # Destination port check
        elif condition_type == 'dst_port':
            return parsed_packet.get('dst_port') == int(condition_value)
        
        # Port check (either src or dst)
        elif condition_type == 'port':
            port = int(condition_value)
            return parsed_packet.get('src_port') == port or parsed_packet.get('dst_port') == port
        
        # Source IP check
        elif condition_type == 'src_ip':
            return parsed_packet.get('src_ip') == str(condition_value)
        
        # Destination IP check
        elif condition_type == 'dst_ip':
            return parsed_packet.get('dst_ip') == str(condition_value)
        
        # Payload string search
        elif condition_type == 'payload_contains':
            payload_text = parsed_packet.get('payload_text', '')
            if payload_text:
                return str(condition_value).lower() in payload_text.lower()
            return False
        
        # Payload regex search
        elif condition_type == 'payload_regex':
            payload_text = parsed_packet.get('payload_text', '')
            if payload_text:
                try:
                    return bool(re.search(condition_value, payload_text, re.IGNORECASE))
                except re.error:
                    print(f"Warning: Invalid regex pattern: {condition_value}")
                    return False
            return False
        
        # Payload size check
        elif condition_type == 'payload_size_gt':
            return parsed_packet.get('payload_size', 0) > int(condition_value)
        
        elif condition_type == 'payload_size_lt':
            return parsed_packet.get('payload_size', 0) < int(condition_value)
        
        # TCP flags check
        elif condition_type == 'tcp_flags':
            flags = parsed_packet.get('flags', '')
            return str(condition_value).upper() in flags.upper()
        
        # DNS query check
        elif condition_type == 'dns_query':
            dns_data = parsed_packet.get('extra', {}).get('dns', {})
            query = dns_data.get('query', '')
            return str(condition_value).lower() in query.lower()
        
        # HTTP method check
        elif condition_type == 'http_method':
            http_data = parsed_packet.get('extra', {}).get('http', {})
            method = http_data.get('method', '')
            return method.upper() == str(condition_value).upper()
        
        # HTTP path check
        elif condition_type == 'http_path_contains':
            http_data = parsed_packet.get('extra', {}).get('http', {})
            path = http_data.get('path', '')
            return str(condition_value) in path
        
        # Default: unknown condition type
        else:
            print(f"Warning: Unknown condition type: {condition_type}")
            return False
