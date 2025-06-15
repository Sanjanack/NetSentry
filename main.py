# main.py
import csv
import random
import time
from datetime import datetime
import os

TEST_MODE = True  # 🔁 Toggle True (dummy alerts) or False (real packet sniffing)

ALERT_FILE = "alerts.csv"

def write_alert(alert_data):
    with open(ALERT_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            alert_data["Time"],
            alert_data["Source IP"],
            alert_data["Destination IP"],
            alert_data["Alert Type"]
        ])
    print(f"[+] Alert: {alert_data}")

def ensure_alert_file():
    if not os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "w") as f:
            writer = csv.writer(f)
            writer.writerow(["Time", "Source IP", "Destination IP", "Alert Type"])

# ---------------- Test Mode ----------------
def generate_fake_alerts():
    print("⚙️  Generating fake alerts... Press Ctrl+C to stop.")
    ALERT_TYPES = ["Port Scan", "DoS", "Brute Force", "Other Packet"]
    try:
        while True:
            alert = {
                "Time": datetime.now().strftime("%H:%M:%S"),
                "Source IP": f"192.168.0.{random.randint(1, 254)}",
                "Destination IP": f"10.0.0.{random.randint(1, 254)}",
                "Alert Type": random.choice(ALERT_TYPES)
            }
            write_alert(alert)
            time.sleep(2)
    except KeyboardInterrupt:
        print("🛑 Stopped fake alert generation.")

# ---------------- Real Mode ----------------
def start_sniffer():
    from scapy.all import sniff, IP
    print("🟢 NetSentry is running... Press Ctrl+C to stop.")

    def packet_callback(packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            alert = {
                "Time": datetime.now().strftime("%H:%M:%S"),
                "Source IP": src,
                "Destination IP": dst,
                "Alert Type": "Other Packet"
            }
            write_alert(alert)

    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("🛑 Stopped packet sniffing.")
    except Exception as e:
        print("❌ Error:", e)

# ---------------- Entry ----------------
ensure_alert_file()
if TEST_MODE:
    generate_fake_alerts()
else:
    start_sniffer()
