import subprocess
import sys
import os
import time
import signal
import webbrowser
from threading import Thread
import json

def run_packet_sniffer():
    """Run the packet sniffer in a separate process."""
    return subprocess.Popen([sys.executable, 'main.py'])

def init_status_file():
    """Initialize the monitoring status file."""
    if not os.path.exists('monitoring_status.json'):
        with open('monitoring_status.json', 'w') as f:
            json.dump({"is_paused": False}, f)

def main():
    print("🚀 Starting NetSentry...")
    
    # Initialize status file
    init_status_file()
    
    # Start packet sniffer
    sniffer_process = run_packet_sniffer()
    print("✅ Packet sniffer started")
    
    # Start Streamlit dashboard
    print("✅ Starting dashboard...")
    os.system('streamlit run dashboard.py')

if __name__ == "__main__":
    main()
