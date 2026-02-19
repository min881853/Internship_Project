#firewall_handler.py

import logging

class FirewallHandler:
    def __init__(self, logger, rules_file='./sdn_module/firewall_rule.txt'):
        self.logger = logger
        self.rules_file = rules_file
        self.firewall_rules = self.load_firewall_rules()

    def load_firewall_rules(self):
        """Load firewall rules from a file."""
        rules = set()
        try:
            with open(self.rules_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):  # Ignore comments and empty lines
                        rules.add(tuple(line.split(',')))  # Add rule as (src_mac, dst_mac)
        except FileNotFoundError:
            self.logger.warning("%s not found. No rules loaded.", self.rules_file)
        return rules

    def is_blocked(self, src_mac, dst_mac):
        """Check if a packet should be blocked."""
        return (src_mac, dst_mac) in self.firewall_rules

