from pymongo import MongoClient
from datetime import datetime, timedelta
import json
import os
from typing import Dict, List, Optional
import sys
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

class SecurityDataStore:
    def __init__(self):
        """Initialize MongoDB connection"""
        try:
            self.client = MongoClient('mongodb://localhost:27017/')
            self.db = self.client['CTI']
            self.collection = self.db['threats']
            print("[+] Connected to MongoDB")
        except Exception as e:
            print(f"[-] MongoDB connection error: {str(e)}")
            sys.exit(1)

        self.alert_thresholds = {
            'cve_score': 7.5,
            'failed_logins': 5,  # Within 5 minutes
            'port_scans': 100    # Connection attempts per minute
        }
        load_dotenv()
        self.smtp_config = {
            'server': os.getenv('SMTP_SERVER'),
            'port': int(os.getenv('SMTP_PORT', 587)),
            'username': os.getenv('SMTP_USERNAME'),
            'password': os.getenv('SMTP_PASSWORD'),
            'recipient': os.getenv('ALERT_EMAIL')
        }

    def store_gemini_data(self, data_file: str) -> None:
        """Store AI threat intelligence data"""
        try:
            with open(data_file, 'r') as f:
                threat_data = json.load(f)
            
            document = {
                'source': 'gemini',
                'timestamp': datetime.now(),
                'data': threat_data,
                'type': 'threat_intel'
            }
            
            self.collection.insert_one(document)
            print("[+] Stored Gemini threat intelligence data")
            
            # Check for alerts after storing
            alert = self.check_alert_conditions(threat_data, 'gemini')
            if alert:
                self.trigger_alert(alert)
            
        except Exception as e:
            print(f"[-] Error storing Gemini data: {str(e)}")

    def store_nmap_data(self, data_file: str) -> None:
        """Store Nmap scan results"""
        try:
            with open(data_file, 'r') as f:
                scan_data = json.load(f)
            
            document = {
                'source': 'nmap',
                'timestamp': datetime.now(),
                'data': scan_data,
                'type': 'network_scan'
            }
            
            self.collection.insert_one(document)
            print("[+] Stored Nmap scan data")
            
        except Exception as e:
            print(f"[-] Error storing Nmap data: {str(e)}")

    def store_zeek_data(self, data_file: str) -> None:
        """Store Zeek monitoring data"""
        try:
            with open(data_file, 'r') as f:
                zeek_data = json.load(f)
            
            document = {
                'source': 'zeek',
                'timestamp': datetime.now(),
                'data': zeek_data,
                'type': 'network_monitor'
            }
            
            self.collection.insert_one(document)
            print("[+] Stored Zeek monitoring data")
            
        except Exception as e:
            print(f"[-] Error storing Zeek data: {str(e)}")

    def store_suricata_data(self, data_file: str) -> None:
        """Store Suricata IDS alerts"""
        try:
            with open(data_file, 'r') as f:
                suricata_data = json.load(f)
            
            document = {
                'source': 'suricata',
                'timestamp': datetime.now(),
                'data': suricata_data,
                'type': 'ids_alert'
            }
            
            self.collection.insert_one(document)
            print("[+] Stored Suricata alert data")
            
        except Exception as e:
            print(f"[-] Error storing Suricata data: {str(e)}")

    def query_threats(self, 
                     source: Optional[str] = None, 
                     start_date: Optional[datetime] = None,
                     end_date: Optional[datetime] = None) -> List[Dict]:
        """Query stored threat data"""
        query = {}
        
        if source:
            query['source'] = source
            
        if start_date or end_date:
            query['timestamp'] = {}
            if start_date:
                query['timestamp']['$gte'] = start_date
            if end_date:
                query['timestamp']['$lte'] = end_date

        try:
            results = list(self.collection.find(query))
            return results
        except Exception as e:
            print(f"[-] Error querying threats: {str(e)}")
            return []

    def check_alert_conditions(self, data: Dict, source: str) -> Optional[Dict]:
        """Check if data meets alert conditions"""
        alert = None
        
        if source == 'gemini':
            # Check CVE scores
            if 'cves' in data:
                high_risk_cves = [
                    cve for cve in data['cves'] 
                    if float(cve.get('cvss_score', 0)) > self.alert_thresholds['cve_score']
                ]
                if high_risk_cves:
                    alert = {
                        'type': 'high_risk_cve',
                        'severity': 'HIGH',
                        'details': f"Found {len(high_risk_cves)} high-risk CVEs",
                        'cves': high_risk_cves
                    }

        elif source == 'suricata':
            # Check failed login attempts
            recent_fails = self.collection.count_documents({
                'source': 'suricata',
                'data.alert.category': 'Authentication Failed',
                'timestamp': {'$gte': datetime.now() - timedelta(minutes=5)}
            })
            if recent_fails >= self.alert_thresholds['failed_logins']:
                alert = {
                    'type': 'brute_force',
                    'severity': 'HIGH',
                    'details': f"Detected {recent_fails} failed login attempts in 5 minutes"
                }

        elif source in ['zeek', 'nmap']:
            # Check for port scanning
            recent_scans = self.collection.count_documents({
                'source': source,
                'type': 'network_scan',
                'timestamp': {'$gte': datetime.now() - timedelta(minutes=1)}
            })
            if recent_scans >= self.alert_thresholds['port_scans']:
                alert = {
                    'type': 'port_scanning',
                    'severity': 'MEDIUM',
                    'details': f"Detected {recent_scans} scan attempts in 1 minute"
                }

        return alert

    def trigger_alert(self, alert: Dict) -> None:
        """Handle alert by storing it and sending notification"""
        try:
            # Store alert in MongoDB
            alert_doc = {
                'timestamp': datetime.now(),
                'type': 'security_alert',
                'alert_data': alert
            }
            self.collection.insert_one(alert_doc)

            # Send email notification
            self.send_alert_email(alert)

            print(f"[!] ALERT: {alert['type']} - {alert['details']}")

        except Exception as e:
            print(f"[-] Error triggering alert: {str(e)}")

    def send_alert_email(self, alert: Dict) -> None:
        """Send email notification for alert"""
        if not all(self.smtp_config.values()):
            return

        try:
            msg = MIMEText(
                f"Security Alert:\nType: {alert['type']}\n"
                f"Severity: {alert['severity']}\n"
                f"Details: {alert['details']}\n"
                f"Time: {datetime.now()}"
            )
            msg['Subject'] = f"Security Alert: {alert['type']}"
            msg['From'] = self.smtp_config['username']
            msg['To'] = self.smtp_config['recipient']

            with smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port']) as server:
                server.starttls()
                server.login(self.smtp_config['username'], self.smtp_config['password'])
                server.send_message(msg)

        except Exception as e:
            print(f"[-] Error sending alert email: {str(e)}")

def main():
    store = SecurityDataStore()
    
    # Example usage
    try:
        # Store Gemini data
        gemini_file = "threat_intel_latest.json"
        if os.path.exists(gemini_file):
            store.store_gemini_data(gemini_file)
        
        # Store Nmap data
        nmap_file = "scan_results/latest_scan.json"
        if os.path.exists(nmap_file):
            store.store_nmap_data(nmap_file)
        
        # Store Zeek data
        zeek_file = "suspicious_activity.json"
        if os.path.exists(zeek_file):
            store.store_zeek_data(zeek_file)
        
        # Store Suricata data
        suricata_file = "suricata_logs/alerts.json"
        if os.path.exists(suricata_file):
            store.store_suricata_data(suricata_file)
        
        # Query example
        print("\n[*] Recent threats from all sources:")
        recent_threats = store.query_threats(
            start_date=datetime.now().replace(hour=0, minute=0)
        )
        for threat in recent_threats:
            print(f"Source: {threat['source']}")
            print(f"Time: {threat['timestamp']}")
            print(f"Type: {threat['type']}\n")
            
    except KeyboardInterrupt:
        print("\n[*] Stopping data collection...")
    except Exception as e:
        print(f"[-] Error: {str(e)}")

if __name__ == "__main__":
    main()