import sqlite3
import pandas as pd
from datetime import datetime, timedelta
import random
import ipaddress

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('netsentry.db')
        self.create_tables()
        self.populate_dummy_data()

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                alert_type TEXT,
                severity TEXT,
                description TEXT,
                packet_size INTEGER,
                packet_count INTEGER
            )
        ''')
        self.conn.commit()

    def generate_realistic_ip(self):
        """Generate a realistic IP address."""
        # Common private IP ranges
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255')
        ]
        # Some public IPs for external threats
        public_ranges = [
            ('1.1.1.1', '1.1.1.255'),  # Cloudflare
            ('8.8.8.0', '8.8.8.255'),  # Google DNS
            ('45.33.0.0', '45.33.255.255')  # Random public range
        ]
        
        # 70% chance of private IP, 30% chance of public IP
        if random.random() < 0.7:
            start, end = random.choice(private_ranges)
        else:
            start, end = random.choice(public_ranges)
            
        start_ip = int(ipaddress.IPv4Address(start))
        end_ip = int(ipaddress.IPv4Address(end))
        return str(ipaddress.IPv4Address(random.randint(start_ip, end_ip)))

    def generate_alert_data(self):
        """Generate realistic alert data."""
        alert_types = {
            'Port Scan': {
                'severities': ['Low', 'Medium', 'High'],
                'ports': [20, 21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080],
                'descriptions': [
                    'Multiple connection attempts to different ports',
                    'Sequential port scanning detected',
                    'Aggressive port scanning activity'
                ]
            },
            'DoS': {
                'severities': ['Medium', 'High', 'Critical'],
                'ports': [80, 443, 8080],
                'descriptions': [
                    'High volume of requests from single source',
                    'SYN flood attack detected',
                    'UDP flood attack in progress'
                ]
            },
            'Brute Force': {
                'severities': ['Medium', 'High'],
                'ports': [22, 23, 3389],
                'descriptions': [
                    'Multiple failed login attempts',
                    'Password brute force attempt detected',
                    'Credential stuffing attack'
                ]
            },
            'Malware': {
                'severities': ['High', 'Critical'],
                'ports': [80, 443, 8080],
                'descriptions': [
                    'Suspicious file download detected',
                    'Known malware signature identified',
                    'Command and control communication'
                ]
            },
            'Phishing': {
                'severities': ['Medium', 'High'],
                'ports': [80, 443],
                'descriptions': [
                    'Suspicious email attachment',
                    'Phishing website access attempt',
                    'Credential harvesting attempt'
                ]
            }
        }

        alerts = []
        base_time = datetime.now()
        
        for i in range(50):  # Generate 50 diverse alerts
            alert_type = random.choice(list(alert_types.keys()))
            alert_info = alert_types[alert_type]
            
            severity = random.choice(alert_info['severities'])
            source_ip = self.generate_realistic_ip()
            dest_ip = self.generate_realistic_ip()
            
            # Ensure source and destination are different
            while dest_ip == source_ip:
                dest_ip = self.generate_realistic_ip()
            
            # Generate realistic port numbers
            if alert_type in ['Port Scan', 'Brute Force']:
                dest_port = random.choice(alert_info['ports'])
                source_port = random.randint(1024, 65535)
            else:
                dest_port = random.choice(alert_info['ports'])
                source_port = random.randint(1024, 65535)
            
            # Generate timestamp within last 24 hours
            timestamp = base_time - timedelta(
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59)
            )
            
            # Generate packet information
            packet_size = random.randint(64, 1500)
            packet_count = random.randint(1, 1000)
            
            alert = {
                'timestamp': timestamp,
                'source_ip': source_ip,
                'destination_ip': dest_ip,
                'source_port': source_port,
                'destination_port': dest_port,
                'protocol': random.choice(['TCP', 'UDP']),
                'alert_type': alert_type,
                'severity': severity,
                'description': random.choice(alert_info['descriptions']),
                'packet_size': packet_size,
                'packet_count': packet_count
            }
            alerts.append(alert)
        
        return alerts

    def populate_dummy_data(self):
        """Populate the database with dummy data."""
        cursor = self.conn.cursor()
        
        # Check if data already exists
        cursor.execute("SELECT COUNT(*) FROM alerts")
        if cursor.fetchone()[0] > 0:
            return
        
        # Generate and insert dummy data
        alerts = self.generate_alert_data()
        for alert in alerts:
            cursor.execute('''
                INSERT INTO alerts (
                    timestamp, source_ip, destination_ip, source_port,
                    destination_port, protocol, alert_type, severity,
                    description, packet_size, packet_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert['timestamp'],
                alert['source_ip'],
                alert['destination_ip'],
                alert['source_port'],
                alert['destination_port'],
                alert['protocol'],
                alert['alert_type'],
                alert['severity'],
                alert['description'],
                alert['packet_size'],
                alert['packet_count']
            ))
        
        self.conn.commit()

    def get_recent_alerts(self, limit=100):
        """Get recent alerts from the database."""
        query = '''
            SELECT * FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?
        '''
        return pd.read_sql_query(query, self.conn, params=(limit,))

    def get_alert_stats(self):
        """Get alert statistics for dashboard."""
        alerts_df = self.get_recent_alerts()
        
        if alerts_df.empty:
            return {
                'total_alerts': 0,
                'alert_types': pd.DataFrame(),
                'top_sources': pd.DataFrame()
            }
        
        # Alert type distribution
        alert_types = alerts_df['alert_type'].value_counts().reset_index()
        alert_types.columns = ['alert_type', 'count']
        
        # Top source IPs
        top_sources = alerts_df['source_ip'].value_counts().head(10).reset_index()
        top_sources.columns = ['source_ip', 'count']
        
        # Count unique alert types
        unique_alert_types = len(alerts_df['alert_type'].unique())
        
        return {
            'total_alerts': len(alerts_df),
            'alert_types': alert_types,
            'top_sources': top_sources,
            'unique_alert_types': unique_alert_types
        }

    def __del__(self):
        self.conn.close() 