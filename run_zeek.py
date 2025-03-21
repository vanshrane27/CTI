import os
import json
import subprocess
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
from typing import Dict, List, Optional
import threading

class ZeekMonitor:
    def __init__(self):
        """Initialize Zeek monitor"""
        self.zeek_logs_dir = "zeek_logs"
        self.processed_logs_dir = "processed_logs"
        self.suspicious_activity_file = "suspicious_activity.json"
        
        # Create necessary directories
        os.makedirs(self.zeek_logs_dir, exist_ok=True)
        os.makedirs(self.processed_logs_dir, exist_ok=True)
        
        # Suspicious patterns to monitor
        self.suspicious_patterns = {
            'conn': {
                'duration': 3600,  # Connections lasting > 1 hour
                'orig_bytes': 1000000  # Large data transfers
            },
            'http': {
                'status_code': ['404', '500'],  # Suspicious HTTP codes
                'user_agent': ['curl', 'wget']  # Basic automation tools
            },
            'dns': {
                'query': ['.xyz', '.top']  # Suspicious TLDs
            }
        }

    def start_zeek(self, interface: str = "eth0") -> None:
        """Start Zeek monitoring on specified interface"""
        try:
            cmd = [
                "zeek",
                "-i", interface,
                "-C",  # No checksums
                f"LogDir={self.zeek_logs_dir}"
            ]
            
            print(f"[*] Starting Zeek monitoring on {interface}")
            self.zeek_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Start log monitoring
            self.start_log_monitor()
            
        except Exception as e:
            print(f"[-] Error starting Zeek: {str(e)}")
            raise

    def start_log_monitor(self) -> None:
        """Start monitoring Zeek log directory"""
        event_handler = ZeekLogHandler(self)
        observer = Observer()
        observer.schedule(event_handler, self.zeek_logs_dir, recursive=False)
        observer.start()
        print("[+] Log monitoring started")

    def parse_log(self, log_file: str) -> List[Dict]:
        """Parse Zeek log file"""
        suspicious_events = []
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                        
                    fields = line.strip().split('\t')
                    log_type = os.path.basename(log_file).split('.')[0]
                    
                    if log_type in self.suspicious_patterns:
                        event = self._check_suspicious(log_type, fields)
                        if event:
                            suspicious_events.append(event)
                            
        except Exception as e:
            print(f"[-] Error parsing log {log_file}: {str(e)}")
            
        return suspicious_events

    def _check_suspicious(self, log_type: str, fields: List[str]) -> Optional[Dict]:
        """Check if log entry matches suspicious patterns"""
        if log_type == 'conn':
            try:
                duration = float(fields[8])
                orig_bytes = int(fields[9])
                
                if (duration > self.suspicious_patterns['conn']['duration'] or
                    orig_bytes > self.suspicious_patterns['conn']['orig_bytes']):
                    return {
                        'timestamp': fields[0],
                        'type': 'suspicious_connection',
                        'src_ip': fields[2],
                        'dst_ip': fields[4],
                        'duration': duration,
                        'bytes': orig_bytes
                    }
            except (IndexError, ValueError):
                pass
                
        elif log_type == 'http':
            try:
                status_code = fields[15]
                user_agent = fields[12]
                
                if (status_code in self.suspicious_patterns['http']['status_code'] or
                    any(agent in user_agent for agent in self.suspicious_patterns['http']['user_agent'])):
                    return {
                        'timestamp': fields[0],
                        'type': 'suspicious_http',
                        'src_ip': fields[2],
                        'uri': fields[9],
                        'user_agent': user_agent,
                        'status_code': status_code
                    }
            except IndexError:
                pass
                
        return None

    def save_suspicious_activity(self, events: List[Dict]) -> None:
        """Save suspicious activities to JSON file"""
        if not events:
            return
            
        try:
            existing_events = []
            if os.path.exists(self.suspicious_activity_file):
                with open(self.suspicious_activity_file, 'r') as f:
                    existing_events = json.load(f)
                    
            existing_events.extend(events)
            
            with open(self.suspicious_activity_file, 'w') as f:
                json.dump(existing_events, f, indent=4)
                
            print(f"[+] Saved {len(events)} suspicious events")
            
        except Exception as e:
            print(f"[-] Error saving suspicious activities: {str(e)}")

class ZeekLogHandler(FileSystemEventHandler):
    def __init__(self, monitor):
        self.monitor = monitor

    def on_created(self, event):
        if event.is_directory:
            return
            
        if event.src_path.endswith('.log'):
            print(f"[*] New log file detected: {event.src_path}")
            time.sleep(1)  # Wait for file to be written
            suspicious_events = self.monitor.parse_log(event.src_path)
            self.monitor.save_suspicious_activity(suspicious_events)

def main():
    try:
        monitor = ZeekMonitor()
        monitor.start_zeek(interface="eth0")  # Change interface as needed
        
        # Keep script running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[*] Stopping Zeek monitoring...")
        if hasattr(monitor, 'zeek_process'):
            monitor.zeek_process.terminate()
        
    except Exception as e:
        print(f"[-] Error: {str(e)}")

if __name__ == "__main__":
    main()