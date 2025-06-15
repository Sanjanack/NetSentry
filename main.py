# main.py
import random
import time
from datetime import datetime
import os
from database import Database
from sklearn.ensemble import IsolationForest
import numpy as np
import json

TEST_MODE = True  # 🔁 Toggle True (dummy alerts) or False (real packet sniffing)
SIMULATION_MODE = True  # 🎮 Toggle True for demo mode with sample alerts

class NetSentry:
    def __init__(self):
        self.db = Database()
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.packet_history = []
        self.is_trained = False
        self.is_paused = False
        self.status_file = "monitoring_status.json"
        self._init_status()

    def _init_status(self):
        """Initialize monitoring status file."""
        if not os.path.exists(self.status_file):
            self._update_status(False)

    def _update_status(self, is_paused):
        """Update monitoring status."""
        with open(self.status_file, 'w') as f:
            json.dump({"is_paused": is_paused}, f)
        self.is_paused = is_paused

    def detect_anomaly(self, packet_features):
        """Detect if the packet is anomalous using Isolation Forest."""
        if not self.is_trained:
            if len(self.packet_history) < 100:
                self.packet_history.append(packet_features)
                return False
            else:
                self.anomaly_detector.fit(np.array(self.packet_history))
                self.is_trained = True
        
        prediction = self.anomaly_detector.predict([packet_features])
        return prediction[0] == -1

    def write_alert(self, alert_data):
        """Write alert to database."""
        if not self.is_paused:
            self.db.add_alert(alert_data)
            print(f"[+] Alert: {alert_data}")

    def generate_simulation_alerts(self):
        """Generate realistic simulation alerts for demo."""
        print("🎮 Starting simulation mode... Press Ctrl+C to stop.")
        
        # Sample data for realistic simulation
        attack_patterns = {
            "Port Scan": {
                "ips": [f"192.168.1.{i}" for i in range(1, 11)],
                "ports": [21, 22, 23, 25, 80, 443, 3306, 3389],
                "severity": "High"
            },
            "DoS": {
                "ips": [f"10.0.0.{i}" for i in range(1, 6)],
                "packet_sizes": [1000, 1500, 2000],
                "severity": "High"
            },
            "Brute Force": {
                "ips": [f"172.16.0.{i}" for i in range(1, 4)],
                "services": ["SSH", "FTP", "RDP"],
                "severity": "Medium"
            }
        }
        
        try:
            while True:
                # Check if monitoring is paused
                if os.path.exists(self.status_file):
                    with open(self.status_file, 'r') as f:
                        status = json.load(f)
                        self.is_paused = status.get("is_paused", False)
                
                if not self.is_paused:
                    # Select random attack pattern
                    attack_type = random.choice(list(attack_patterns.keys()))
                    pattern = attack_patterns[attack_type]
                    
                    # Generate alert based on pattern
                    if attack_type == "Port Scan":
                        src_ip = random.choice(pattern["ips"])
                        dst_ip = f"192.168.1.{random.randint(100, 200)}"
                        port = random.choice(pattern["ports"])
                        alert = {
                            "Time": datetime.now().strftime("%H:%M:%S"),
                            "Source IP": src_ip,
                            "Destination IP": dst_ip,
                            "Alert Type": attack_type,
                            "Severity": pattern["severity"],
                            "Details": f"Port {port} scan detected"
                        }
                    elif attack_type == "DoS":
                        src_ip = random.choice(pattern["ips"])
                        dst_ip = f"10.0.0.{random.randint(100, 200)}"
                        size = random.choice(pattern["packet_sizes"])
                        alert = {
                            "Time": datetime.now().strftime("%H:%M:%S"),
                            "Source IP": src_ip,
                            "Destination IP": dst_ip,
                            "Alert Type": attack_type,
                            "Severity": pattern["severity"],
                            "Details": f"Large packet ({size} bytes) flood detected"
                        }
                    else:  # Brute Force
                        src_ip = random.choice(pattern["ips"])
                        dst_ip = f"172.16.0.{random.randint(100, 200)}"
                        service = random.choice(pattern["services"])
                        alert = {
                            "Time": datetime.now().strftime("%H:%M:%S"),
                            "Source IP": src_ip,
                            "Destination IP": dst_ip,
                            "Alert Type": attack_type,
                            "Severity": pattern["severity"],
                            "Details": f"Multiple failed {service} login attempts"
                        }
                    
                    self.write_alert(alert)
                
                time.sleep(random.uniform(1, 3))  # Random delay between alerts
                
        except KeyboardInterrupt:
            print("🛑 Stopped simulation.")

    def start_sniffer(self):
        """Start real packet sniffing."""
        from scapy.all import sniff, IP, TCP, UDP
        print("🟢 NetSentry is running... Press Ctrl+C to stop.")

        def packet_callback(packet):
            # Check if monitoring is paused
            if os.path.exists(self.status_file):
                with open(self.status_file, 'r') as f:
                    status = json.load(f)
                    self.is_paused = status.get("is_paused", False)
            
            if not self.is_paused and IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                
                # Extract packet features
                packet_size = len(packet)
                port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
                
                # Detect anomalies
                packet_features = [packet_size, 1, port]  # Simplified features
                is_anomaly = self.detect_anomaly(packet_features)
                
                alert = {
                    "Time": datetime.now().strftime("%H:%M:%S"),
                    "Source IP": src,
                    "Destination IP": dst,
                    "Alert Type": "Anomaly" if is_anomaly else "Normal Traffic",
                    "Severity": "High" if is_anomaly else "Low",
                    "Details": f"Packet size: {packet_size}, Port: {port}"
                }
                self.write_alert(alert)

        try:
            sniff(prn=packet_callback, store=0)
        except KeyboardInterrupt:
            print("🛑 Stopped packet sniffing.")
        except Exception as e:
            print("❌ Error:", e)

if __name__ == "__main__":
    netsentry = NetSentry()
    if TEST_MODE:
        if SIMULATION_MODE:
            netsentry.generate_simulation_alerts()
        else:
            netsentry.generate_fake_alerts()
    else:
        netsentry.start_sniffer()
