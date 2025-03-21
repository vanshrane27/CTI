import tkinter as tk
from tkinter import ttk, scrolledtext
import requests
import json
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime
import subprocess
from typing import Dict, List, Optional

class SecurityDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Monitoring Dashboard")
        self.root.state('zoomed')  # Maximize window
        self.api_key = "your-secret-key"  # Load from env in production
        self.api_url = "http://localhost:5000/api/v1"
        
        # Setup UI components
        self.setup_ui()
        
        # Start automatic updates
        self.update_thread = threading.Thread(target=self.auto_update, daemon=True)
        self.update_thread.start()

    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Top section - Statistics and Controls
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, padx=5, pady=5)

        # Stats labels
        self.stats_frame = ttk.LabelFrame(top_frame, text="Statistics")
        self.stats_frame.pack(side=tk.LEFT, padx=5)
        
        self.total_threats_label = ttk.Label(self.stats_frame, text="Total Threats: 0")
        self.total_threats_label.pack(side=tk.LEFT, padx=5)
        
        self.total_alerts_label = ttk.Label(self.stats_frame, text="Active Alerts: 0")
        self.total_alerts_label.pack(side=tk.LEFT, padx=5)

        # Control buttons
        controls_frame = ttk.Frame(top_frame)
        controls_frame.pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(controls_frame, text="Rescan All", 
                  command=self.rescan_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(controls_frame, text="Refresh Data", 
                  command=self.refresh_data).pack(side=tk.LEFT, padx=2)

        # Main content area
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Left panel - Threat Intelligence
        left_panel = ttk.LabelFrame(content_frame, text="Threat Intelligence")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.threats_text = scrolledtext.ScrolledText(left_panel, wrap=tk.WORD)
        self.threats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Right panel - Security Logs
        right_panel = ttk.Frame(content_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Tabs for different log sources
        log_tabs = ttk.Notebook(right_panel)
        log_tabs.pack(fill=tk.BOTH, expand=True)

        # Nmap tab
        nmap_frame = ttk.Frame(log_tabs)
        log_tabs.add(nmap_frame, text="Nmap Scan")
        self.nmap_text = scrolledtext.ScrolledText(nmap_frame, wrap=tk.WORD)
        self.nmap_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Zeek tab
        zeek_frame = ttk.Frame(log_tabs)
        log_tabs.add(zeek_frame, text="Zeek Monitor")
        self.zeek_text = scrolledtext.ScrolledText(zeek_frame, wrap=tk.WORD)
        self.zeek_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Suricata tab
        suricata_frame = ttk.Frame(log_tabs)
        log_tabs.add(suricata_frame, text="Suricata Alerts")
        self.suricata_text = scrolledtext.ScrolledText(suricata_frame, wrap=tk.WORD)
        self.suricata_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Bottom panel - Charts
        self.setup_charts(main_frame)

    def setup_charts(self, parent):
        charts_frame = ttk.LabelFrame(parent, text="Security Analytics")
        charts_frame.pack(fill=tk.X, pady=5)

        # Create matplotlib figure
        self.fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
        self.fig.tight_layout(pad=3.0)

        # Embed in Tkinter
        canvas = FigureCanvasTkAgg(self.fig, master=charts_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.X, padx=5, pady=5)

        self.ax1, self.ax2 = ax1, ax2

    def update_charts(self, stats_data):
        self.ax1.clear()
        self.ax2.clear()

        # Severity distribution pie chart
        severities = [x['_id'] for x in stats_data['severity_distribution']]
        counts = [x['count'] for x in stats_data['severity_distribution']]
        self.ax1.pie(counts, labels=severities, autopct='%1.1f%%')
        self.ax1.set_title('Alert Severity Distribution')

        # Threat sources bar chart
        sources = ['Nmap', 'Zeek', 'Suricata']
        values = [stats_data['total_threats'], 
                 stats_data.get('zeek_alerts', 0),
                 stats_data.get('suricata_alerts', 0)]
        self.ax2.bar(sources, values)
        self.ax2.set_title('Threats by Source')
        
        self.fig.canvas.draw()

    def refresh_data(self):
        """Refresh all data from API"""
        try:
            # Get threats
            response = requests.get(
                f"{self.api_url}/threats",
                headers={"X-API-Key": self.api_key}
            )
            threats_data = response.json()
            
            self.threats_text.delete(1.0, tk.END)
            for threat in threats_data['data']:
                self.threats_text.insert(tk.END, 
                    f"[{threat['timestamp']}] {threat['source']}: {threat['data']}\n\n")

            # Get stats
            response = requests.get(
                f"{self.api_url}/stats",
                headers={"X-API-Key": self.api_key}
            )
            stats_data = response.json()['data']
            
            self.total_threats_label.config(
                text=f"Total Threats: {stats_data['total_threats']}")
            self.total_alerts_label.config(
                text=f"Active Alerts: {stats_data['total_alerts']}")
            
            self.update_charts(stats_data)

        except Exception as e:
            print(f"Error refreshing data: {e}")

    def rescan_all(self):
        """Trigger all security scans"""
        def run_scans():
            try:
                # Run Nmap scan
                subprocess.run(["python", "run_nmap.py"])
                
                # Run Zeek
                subprocess.run(["python", "run_zeek.py"])
                
                # Run Suricata
                subprocess.run(["python", "run_suricata.py"])
                
                # Refresh data
                self.refresh_data()
                
            except Exception as e:
                print(f"Error during rescan: {e}")

        # Run in separate thread
        threading.Thread(target=run_scans, daemon=True).start()

    def auto_update(self):
        """Auto update data every 60 seconds"""
        while True:
            self.refresh_data()
            threading.Event().wait(60)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityDashboard(root)
    root.mainloop()