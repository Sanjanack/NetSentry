# 🛡️ NetSentry - Network Intrusion Detection System

NetSentry is a lightweight, user-friendly Network Intrusion Detection System (NIDS) designed for small organizations and individuals who need basic network security monitoring without the complexity of enterprise solutions.

## Features

- 🔍 Real-time network traffic monitoring
- 🚨 Detection of common attack patterns:
  - Port scanning
  - DoS attacks
  - Brute force attempts
  - Anomalous traffic patterns
- 📊 Interactive dashboard with:
  - Real-time alerts
  - Attack type distribution
  - Top source IPs
  - Alert frequency over time
- 🔐 Basic authentication
- 📥 Export alerts to CSV
- 🤖 Machine learning-based anomaly detection

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/netsentry.git
cd netsentry
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the packet sniffer (requires admin/root privileges):
```bash
python main.py
```

2. Launch the dashboard:
```bash
streamlit run dashboard.py
```

3. Access the dashboard at `http://localhost:8501`

Default credentials:
- Username: admin
- Password: admin123

## Configuration

- Edit `config.yaml` to modify authentication settings
- Toggle `TEST_MODE` in `main.py` to switch between real packet sniffing and test mode

## Security Note

This is a basic NIDS for educational and small-scale use. For production environments, consider:
- Using stronger authentication
- Implementing proper logging
- Adding more sophisticated detection rules
- Using a proper database system

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.