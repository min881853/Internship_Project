import time
import logging
import os
import csv
import random
import pandas as pd
from datetime import datetime
from collections import defaultdict

# Import AI Agent
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'training', 'ai_agent'))
from test import OllamaAgent

class MockDatapath:
    def __init__(self, id):
        self.id = id

class MockParser:
    def __init__(self):
        pass

class MockFlowStatsHandler:
    """Mock version of Ryu application for handling flow statistics and DDoS detection using AI Agent."""

    SERVER_SRC = "00:00:00:00:00:13"

    def __init__(self):
        """Initialize the mock application."""
        self._setup_logging()

        # File paths for CSV outputs
        self.output_file = os.path.join(os.path.dirname(__file__), 'dummy_flow_stats.csv')
        self.action_log_file = os.path.join(os.path.dirname(__file__), 'dummy_action_log.csv')
        self.start_time = time.time()
        self.seconds_since_start = 0

        # Cache for DDoS detection counts, separated by datapath
        self.ddos_detection_count = defaultdict(lambda: defaultdict(int))
        self.action_log = []

        # Map protocol numbers to names
        self.protocol_map = {1: 'ICMP', 6: 'TCP'}

        # Mock datapaths
        self.datapaths = {1: MockDatapath(1), 2: MockDatapath(2)}
        self.parser = MockParser()

        # Initialize action log CSV
        self._init_action_log_csv()
        self._create_csv_headers()

        # Initialize Ollama AI Agent
        self.ai_agent = OllamaAgent()
        self.logger.info("Mock Flow Stats Handler initialized. Using Ollama AI Agent for classification.")

    def _setup_logging(self):
        """Configure logging with a clear format."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s | %(levelname)s | %(message)s',
            handlers=[logging.StreamHandler()]
        )
        self.logger = logging.getLogger(__name__)

    def _create_csv_headers(self):
        """Create headers for flow stats CSV file."""
        if not os.path.exists(self.output_file):
            headers = [
                'Seconds Since Start', 'Real Timestamp', 'Ethernet Src', 'Ethernet Dst', 'Protocol',
                'Packet Count', 'Byte Count', 'Packet Rate', 'Byte Rate', 'CPU utilization',
                'Duration (sec)', 'Duration (nsec)', 'Prediction', 'Priority', 'Idle Timeout',
                'Hard Timeout', 'Datapath', 'Match Fields', 'Instructions'
            ]
            with open(self.output_file, 'w', newline='') as f:
                csv.writer(f).writerow(headers)

    def _init_action_log_csv(self):
        """Initialize action log CSV file."""
        if not os.path.exists(self.action_log_file):
            headers = ['Seconds Since Start', 'Datapath', 'Eth Src', 'Eth Dst', 'Count', 'Action']
            with open(self.action_log_file, 'w', newline='') as f:
                csv.writer(f).writerow(headers)

    def _get_cpu_utilization(self):
        """Mock CPU utilization."""
        return random.uniform(10, 90)  # Random value for simulation

    def _log_action(self, datapath_id, eth_src, eth_dst, count, action):
        """Log mitigation action to CSV file."""
        seconds_since_start = self.seconds_since_start
        self.action_log.append((seconds_since_start, datapath_id, eth_src, eth_dst, count, action))
        with open(self.action_log_file, 'a', newline='') as f:
            csv.writer(f).writerow([seconds_since_start, datapath_id, eth_src, eth_dst, count, action])

    def _detect_ddos(self, datapath, parser, features, eth_src, eth_dst, protocol, duration):
        """Detect DDoS attacks using AI Agent with ML model predictions and probability scores."""
        proto_name = self.protocol_map.get(protocol, "Unknown")

        try:
            # Extract features
            packet_count = features['Packet Count'].iloc[0]
            byte_count = features['Byte Count'].iloc[0]
            packet_rate = features['Packet Rate'].iloc[0]
            byte_rate = features['Byte Rate'].iloc[0]
            cpu_utilization = features['CPU utilization'].iloc[0]

            # Use Ollama AI Agent for classification
            proto_name_for_query = "ICMP" if protocol == 1 else "TCP"
            query = f"Classify this {proto_name_for_query} traffic: packet_count={packet_count}, byte_count={byte_count}, packet_rate={packet_rate:.2f}, byte_rate={byte_rate:.2f}, cpu_utilization={cpu_utilization:.2f}"
            
            self.logger.info(f"[Agent Query] {query}")
            agent_response = self.ai_agent.run_turn(query)
            self.logger.info(f"[Agent Response] {agent_response}")
            
            # Parse agent response to extract prediction and probabilities
            prediction_base = "Unknown"
            confidence = 0.0
            prob_dict = {}
            
            # Extract prediction from response (look for PREDICTION: DDoS or PREDICTION: Normal)
            import re
            pred_match = re.search(r'PREDICTION:\s*([^\n]+)', agent_response, re.IGNORECASE)
            if pred_match:
                pred_text = pred_match.group(1).strip()
                prediction_base = pred_text
            
            # Extract confidence score
            conf_match = re.search(r'CONFIDENCE:\s*([\d.]+)\s*%?', agent_response, re.IGNORECASE)
            if conf_match:
                try:
                    confidence = float(conf_match.group(1)) / 100.0  # Convert percentage to decimal
                except ValueError:
                    confidence = 0.0
            
            # Extract probability scores
            probs_match = re.search(r'PROBABILITIES:\s*([^\n]+)', agent_response, re.IGNORECASE)
            if probs_match:
                probs_text = probs_match.group(1)
                # Parse format like "DDoS_TCP: 0.955, Normal_TCP: 0.045" or "DDoS_TCP: 95.5%, Normal_TCP: 4.5%"
                for item in probs_text.split(','):
                    if ':' in item:
                        try:
                            cls, prob = item.split(':')
                            prob_str = prob.strip().rstrip('%')  # Remove % if present
                            prob_val = float(prob_str)
                            # If in percentage format (>1), convert to decimal
                            if prob_val > 1:
                                prob_val = prob_val / 100.0
                            prob_dict[cls.strip()] = prob_val
                        except ValueError:
                            pass  # Skip parsing errors
            
            # Convert to standard prediction format
            if "DDoS" in prediction_base.upper():
                if protocol == 1:  # ICMP
                    prediction = "DDoS_ICMP"
                elif protocol == 6:  # TCP
                    prediction = "DDoS_TCP"
                else:
                    prediction = "Unknown"
            else:
                if protocol == 1:  # ICMP
                    prediction = "Normal_ICMP"
                elif protocol == 6:  # TCP
                    prediction = "Normal_TCP"
                else:
                    prediction = "Unknown"

            if duration == 0 or eth_src == self.SERVER_SRC:
                return prediction

            self.logger.info(f"\nTraffic Analysis from ap{datapath.id} (AI Agent + ML Model):")
            self.logger.info(f"  Source: {eth_src} -> Destination: {eth_dst}")
            self.logger.info(f"  Protocol: {proto_name}")
            self.logger.info(f"  Prediction: {prediction}")
            self.logger.info(f"  CPU Usage: {cpu_utilization:.2f}%")
            self.logger.info(f"  Confidence: {confidence*100:.2f}%")
            self.logger.info(f"  Probabilities:")
            for cls, prob in prob_dict.items():
                self.logger.info(f"    {cls}: {prob:.4f}")

            dpid = datapath.id
            if prediction in ["DDoS_ICMP", "DDoS_TCP"] and confidence >= 0.9:
                self.ddos_detection_count[dpid][eth_src] += 1
                count = self.ddos_detection_count[dpid][eth_src]
                self.logger.info(f"  Detection count for dp:{dpid}, src:{eth_src} = {count}")

                if count > 4:
                    self.logger.info(f"\033[31m*** Permanent block triggered for {eth_src} ***\033[0m")
                    self._log_action(dpid, eth_src, eth_dst, count, "perm_block")
                elif count > 2:
                    self.logger.info(f"\033[31mTemporary block triggered for {eth_src}\033[0m")
                    self._log_action(dpid, eth_src, eth_dst, count, "temp_block")
            elif prediction in ["DDoS_ICMP", "DDoS_TCP"] and confidence >= 0.5:
                self.logger.info(f"  Rate Limiting triggered for {eth_src}")
                self._log_action(dpid, eth_src, eth_dst, 0, f"rate_limit_100")
            return prediction
        except Exception as e:
            self.logger.error(f"AI Agent classification error for {proto_name}: {e}")
            return "Unknown"

    def simulate_flow_stats(self):
        """Simulate processing flow statistics."""
        self.seconds_since_start = int(time.time() - self.start_time)
        real_timestamp = datetime.fromtimestamp(self.start_time + self.seconds_since_start).strftime('%Y-%m-%d %H:%M:%S')

        # Mock some flows
        mock_flows = [
            {
                'eth_src': '00:00:00:00:00:01',
                'eth_dst': '00:00:00:00:00:13',
                'ip_proto': 6,  # TCP
                'packet_count': random.randint(100, 1000),
                'byte_count': random.randint(10000, 100000),
                'duration_sec': random.randint(1, 10),
                'duration_nsec': random.randint(0, 999999999),
                'priority': 1,
                'idle_timeout': 0,
                'hard_timeout': 0,
                'instructions': [{'type': 'OFPIT_APPLY_ACTIONS', 'actions': []}]
            },
            {
                'eth_src': '00:00:00:00:00:02',
                'eth_dst': '00:00:00:00:00:13',
                'ip_proto': 1,  # ICMP
                'packet_count': random.randint(50, 500),
                'byte_count': random.randint(5000, 50000),
                'duration_sec': random.randint(1, 10),
                'duration_nsec': random.randint(0, 999999999),
                'priority': 1,
                'idle_timeout': 0,
                'hard_timeout': 0,
                'instructions': [{'type': 'OFPIT_APPLY_ACTIONS', 'actions': []}]
            }
        ]

        cpu_util = self._get_cpu_utilization()

        with open(self.output_file, 'a', newline='') as f:
            writer = csv.writer(f)
            for flow in mock_flows:
                datapath = random.choice(list(self.datapaths.values()))
                eth_src = flow['eth_src']
                eth_dst = flow['eth_dst']
                protocol = flow['ip_proto']
                proto_name = self.protocol_map.get(protocol, "Unknown")
                duration = flow['duration_sec'] + (flow['duration_nsec'] / 1e9)
                pkt_rate = flow['packet_count'] / (duration + 1e-6)
                byte_rate = flow['byte_count'] / (duration + 1e-6)

                features = pd.DataFrame([{
                    'Packet Count': flow['packet_count'],
                    'Byte Count': flow['byte_count'],
                    'Packet Rate': pkt_rate,
                    'Byte Rate': byte_rate,
                    'CPU utilization': cpu_util
                }])

                prediction = self._detect_ddos(datapath, self.parser, features, eth_src, eth_dst, protocol, duration)

                writer.writerow([
                    self.seconds_since_start, real_timestamp, eth_src, eth_dst, proto_name,
                    flow['packet_count'], flow['byte_count'], f"{pkt_rate:.2f}", f"{byte_rate:.2f}",
                    cpu_util, flow['duration_sec'], flow['duration_nsec'], prediction,
                    flow['priority'], flow['idle_timeout'], flow['hard_timeout'], datapath.id,
                    f"eth_src={eth_src},eth_dst={eth_dst},ip_proto={protocol}", str(flow['instructions'])
                ])

    def run_simulation(self):
        """Run the mock simulation."""
        self.logger.info("Starting mock simulation...")
        try:
            while True:
                self.simulate_flow_stats()
                time.sleep(5)  # Simulate every 5 seconds
        except KeyboardInterrupt:
            self.logger.info("Simulation stopped.")

if __name__ == "__main__":
    handler = MockFlowStatsHandler()
    handler.run_simulation()