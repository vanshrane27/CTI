import os
import json
import subprocess
import signal
import sys
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import yaml
import threading
import time

class SuricataMonitor:
    def __init__(self):
        """Initialize Suricata monitor"""
        self.config = {
            'log_dir': 'suricata_logs',
            'config_path': '/etc/suricata/suricata.yaml',
            'rules_path': '/etc/suricata/rules',
            'alert_log': 'fast.log',
            'eve_log': 'eve.json'
        }
        
        # Create log directory
        os.makedirs(self.config['log_dir'], exist_ok=True)
        
        # Initialize alert counters
        self.alert_stats = {
            'total_alerts': 0,
            'severity_counts': {
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            }
        }
        
        # Setup signal handling
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def start_suricata(self, interface: str = "eth0") -> None:
        """Start Suricata IDS"""
        try:
            # Verify Suricata installation
            self._check_suricata_installation()
            
            # Build command
            cmd = [
                "suricata",
                "-c", self.config['config_path'],
                "-i", interface,
                "--set", f"default-log-dir={self.config['log_dir']}"
            ]
            
            print(f"[*] Starting Suricata on interface {interface}")
            self.suricata_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Start log monitoring threads
            self._start_monitoring()
            
        except Exception as e:
            print(f"[-] Error starting Suricata: {str(e)}")
            sys.exit(1)

    def _check_suricata_installation(self) -> None:
        """Verify Suricata installation and configuration"""
        try:
            subprocess.run(["suricata", "--build-info"], 
                         check=True, 
                         capture_output=True)
        except subprocess.CalledProcessError:
            raise Exception("Suricata not found. Please install Suricata first.")
        
        if not os.path.exists(self.config['config_path']):
            raise Exception("Suricata configuration file not found.")

    def _start_monitoring(self) -> None:
        """Start monitoring threads for different log files"""
        self.monitoring = True
        
        # Monitor eve.json for detailed alerts
        self.eve_thread = threading.Thread(
            target=self._monitor_eve_log,
            daemon=True
        )
        self.eve_thread.start()
        
        # Monitor fast.log for quick alerts
        self.fast_thread = threading.Thread(
            target=self._monitor_fast_log,
            daemon=True
        )
        self.fast_thread.start()

    def _monitor_eve_log(self) -> None:
        """Monitor eve.json for detailed alert information"""
        eve_log_path = os.path.join(self.config['log_dir'], self.config['eve_log'])
        
        while self.monitoring:
            if os.path.exists(eve_log_path):
                try:
                    with open(eve_log_path, 'r') as f:
                        f.seek(0, 2)  # Go to end of file
                        while self.monitoring:
                            line = f.readline()
                            if line:
                                self._process_eve_alert(line)
                            else:
                                time.sleep(0.1)
                except Exception as e:
                    print(f"[-] Error monitoring eve.json: {str(e)}")
                    time.sleep(1)
            else:
                time.sleep(1)

    def _monitor_fast_log(self) -> None:
        """Monitor fast.log for quick alert information"""
        fast_log_path = os.path.join(self.config['log_dir'], self.config['alert_log'])
        
        while self.monitoring:
            if os.path.exists(fast_log_path):
                try:
                    with open(fast_log_path, 'r') as f:
                        f.seek(0, 2)
                        while self.monitoring:
                            line = f.readline()
                            if line:
                                self._process_fast_alert(line)
                            else:
                                time.sleep(0.1)
                except Exception as e:
                    print(f"[-] Error monitoring fast.log: {str(e)}")
                    time.sleep(1)
            else:
                time.sleep(1)

    def _process_eve_alert(self, line: str) -> None:
        """Process and categorize alerts from eve.json"""
        try:
            alert_data = json.loads(line)
            if alert_data.get('event_type') == 'alert':
                severity = self._determine_severity(alert_data)
                self.alert_stats['total_alerts'] += 1
                self.alert_stats['severity_counts'][severity] += 1
                
                self._log_alert({
                    'timestamp': alert_data.get('timestamp'),
                    'signature': alert_data.get('alert', {}).get('signature'),
                    'category': alert_data.get('alert', {}).get('category'),
                    'severity': severity,
                    'src_ip': alert_data.get('src_ip'),
                    'dest_ip': alert_data.get('dest_ip'),
                    'proto': alert_data.get('proto')
                })
                
        except json.JSONDecodeError:
            pass

    def _process_fast_alert(self, line: str) -> None:
        """Process alerts from fast.log"""
        if line.strip():
            print(f"[ALERT] {line.strip()}")

    def _determine_severity(self, alert_data: Dict) -> str:
        """Determine alert severity based on priority"""
        priority = alert_data.get('alert', {}).get('severity', 3)
        if priority <= 1:
            return 'HIGH'
        elif priority == 2:
            return 'MEDIUM'
        return 'LOW'

    def _log_alert(self, alert_data: Dict) -> None:
        """Log formatted alert data"""
        print("\n[ALERT DETECTED]")
        print(f"Timestamp: {alert_data['timestamp']}")
        print(f"Signature: {alert_data['signature']}")
        print(f"Severity: {alert_data['severity']}")
        print(f"Source IP: {alert_data['src_ip']}")
        print(f"Destination IP: {alert_data['dest_ip']}")
        print(f"Protocol: {alert_data['proto']}\n")

    def _handle_shutdown(self, signum, frame) -> None:
        """Handle graceful shutdown"""
        print("\n[*] Shutting down Suricata monitor...")
        self.monitoring = False
        if hasattr(self, 'suricata_process'):
            self.suricata_process.terminate()
        self._print_stats()
        sys.exit(0)

    def _print_stats(self) -> None:
        """Print alert statistics"""
        print("\n[ALERT STATISTICS]")
        print(f"Total Alerts: {self.alert_stats['total_alerts']}")
        print("Severity Distribution:")
        for severity, count in self.alert_stats['severity_counts'].items():
            print(f"  {severity}: {count}")

def main():
    monitor = SuricataMonitor()
    monitor.start_suricata(interface="eth0")  # Change interface as needed
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()