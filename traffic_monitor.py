import os
import subprocess
from datetime import datetime

# Directory to store logs
LOG_DIR = "/var/log/server_traffic_monitor"
TRAFFIC_LOG = f"{LOG_DIR}/traffic_log.txt"
SUSPICIOUS_LOG = f"{LOG_DIR}/suspicious_traffic_log.txt"

# Ensure the log directory exists
os.makedirs(LOG_DIR, exist_ok=True)


def run_tcpdump(duration=60):
    """
    Run tcpdump to capture network traffic for a specified duration.
    Logs the captured data to a file.
    """
    print("Starting tcpdump to capture traffic...")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    pcap_file = f"{LOG_DIR}/traffic_{timestamp}.pcap"

    try:
        # Run tcpdump for the specified duration
        subprocess.run(
            ["tcpdump", "-i", "any", "-w", pcap_file, "-G", str(duration), "-W", "1"],
            check=True,
        )
        print(f"Traffic captured in file: {pcap_file}")
        return pcap_file
    except subprocess.CalledProcessError as e:
        print(f"Error running tcpdump: {e}")
        return None


def analyze_pcap_file(pcap_file):
    """
    Analyze the captured pcap file using tcpdump and extract insights.
    """
    print(f"Analyzing captured traffic from {pcap_file}...")
    try:
        result = subprocess.run(
            ["tcpdump", "-nn", "-r", pcap_file],
            capture_output=True,
            text=True,
            check=True,
        )
        traffic_data = result.stdout

        # Log the traffic data
        with open(TRAFFIC_LOG, "a") as log_file:
            log_file.write(f"Traffic analysis from {pcap_file} at {datetime.now()}\n")
            log_file.write(traffic_data)
            log_file.write("\n" + "=" * 80 + "\n")
        print(f"Traffic analysis logged to {TRAFFIC_LOG}")
        return traffic_data
    except subprocess.CalledProcessError as e:
        print(f"Error analyzing traffic: {e}")
        return None


def detect_suspicious_traffic(traffic_data):
    """
    Detect suspicious traffic patterns based on common indicators.
    Logs the suspicious activities to a separate log file.
    """
    print("Detecting suspicious traffic patterns...")
    suspicious_patterns = [
        "Nmap scan",  # Example: Detect Nmap scanning activity
        "syn flood",  # SYN Flood attacks
        "malicious",  # Generic suspicious keywords
        "unauthorized access",  # Unauthorized access attempts
    ]
    suspicious_lines = []

    for line in traffic_data.splitlines():
        if any(pattern.lower() in line.lower() for pattern in suspicious_patterns):
            suspicious_lines.append(line)

    if suspicious_lines:
        print("Suspicious activity detected:")
        for item in suspicious_lines:
            print(f"  - {item}")

        # Log the suspicious entries
        with open(SUSPICIOUS_LOG, "a") as log_file:
            log_file.write(f"Suspicious traffic detected at {datetime.now()}\n")
            log_file.write("\n".join(suspicious_lines))
            log_file.write("\n" + "=" * 80 + "\n")

        print(f"Suspicious activities logged to {SUSPICIOUS_LOG}")
    else:
        print("No suspicious activity detected.")


def monitor_live_traffic(duration=60):
    """
    Use iftop for live traffic monitoring for the specified duration.
    """
    print("Starting iftop for live traffic monitoring...")
    try:
        # Run iftop in capture mode for the specified duration
        subprocess.run(["iftop", "-t", "-s", str(duration)], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running iftop: {e}")


def main():
    print("Starting server traffic monitoring...")

    # Step 1: Run tcpdump to capture traffic
    pcap_file = run_tcpdump(duration=60)
    if pcap_file:
        # Step 2: Analyze captured traffic
        traffic_data = analyze_pcap_file(pcap_file)

        if traffic_data:
            # Step 3: Detect suspicious traffic patterns
            detect_suspicious_traffic(traffic_data)

    # Step 4: (Optional) Monitor live traffic using iftop
    monitor_live_traffic(duration=60)

    print("Traffic monitoring completed.")


if __name__ == "__main__":
    main()
