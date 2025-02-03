import os
import subprocess
from datetime import datetime

# Log files
LOG_DIR = "/var/log/rootkit_scan"
CHKROOTKIT_LOG = f"{LOG_DIR}/chkrootkit_scan.log"
RKHUNTER_LOG = f"{LOG_DIR}/rkhunter_scan.log"
INFECTED_LOG = f"{LOG_DIR}/rootkit_infected_ips.txt"

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)


def run_chkrootkit_scan():
    """Run Chkrootkit scan and log the results."""
    print("Running Chkrootkit scan...")
    try:
        result = subprocess.run(["chkrootkit"], capture_output=True, text=True, check=True)
        scan_output = result.stdout

        # Log the results
        with open(CHKROOTKIT_LOG, "a") as log_file:
            log_file.write(f"Scan run on: {datetime.now()}\n")
            log_file.write(scan_output)
            log_file.write("\n" + "=" * 80 + "\n")
        print(f"Chkrootkit results saved to {CHKROOTKIT_LOG}")
        return scan_output
    except subprocess.CalledProcessError as e:
        print(f"Error running Chkrootkit: {e}")
        return None


def run_rkhunter_scan():
    """Run RKHunter scan and log the results."""
    print("Running RKHunter scan...")
    try:
        result = subprocess.run(["rkhunter", "--check", "--sk"], capture_output=True, text=True, check=True)
        scan_output = result.stdout

        # Log the results
        with open(RKHUNTER_LOG, "a") as log_file:
            log_file.write(f"Scan run on: {datetime.now()}\n")
            log_file.write(scan_output)
            log_file.write("\n" + "=" * 80 + "\n")
        print(f"RKHunter results saved to {RKHUNTER_LOG}")
        return scan_output
    except subprocess.CalledProcessError as e:
        print(f"Error running RKHunter: {e}")
        return None


def analyze_scan_results(scan_output, tool_name):
    """Analyze scan results from a tool and log suspicious activities."""
    print(f"Analyzing {tool_name} scan results...")
    suspicious_lines = []

    for line in scan_output.splitlines():
        if "INFECTED" in line or "WARNING" in line or "suspicious" in line.lower():
            suspicious_lines.append(line)

    if suspicious_lines:
        print(f"Suspicious activity detected by {tool_name}:")
        for item in suspicious_lines:
            print(f"  - {item}")

        # Log the suspicious entries
        with open(INFECTED_LOG, "a") as infected_log:
            infected_log.write(f"Suspicious activity detected by {tool_name} on: {datetime.now()}\n")
            infected_log.write("\n".join(suspicious_lines))
            infected_log.write("\n" + "=" * 80 + "\n")

        print(f"Suspicious entries logged to {INFECTED_LOG}")
    else:
        print(f"No suspicious activity detected by {tool_name}.")


def main():
    print("Starting integrated rootkit detection automation...")

    # Run Chkrootkit scan
    chkrootkit_output = run_chkrootkit_scan()
    if chkrootkit_output:
        analyze_scan_results(chkrootkit_output, "Chkrootkit")

    # Run RKHunter scan
    rkhunter_output = run_rkhunter_scan()
    if rkhunter_output:
        analyze_scan_results(rkhunter_output, "RKHunter")

    print("Rootkit detection automation completed.")


if __name__ == "__main__":
    main()
