import multiprocessing
import subprocess
import signal
import sys

# Function to run a script in a subprocess
def run_script(script_name):
    try:
        process = subprocess.Popen(["python3", script_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()
    except Exception as e:
        print(f"Error running {script_name}: {e}")

# Graceful exit when user presses Ctrl+C
def signal_handler(sig, frame):
    print("\n[INFO] Stopping all monitoring processes...")
    for process in processes:
        process.terminate()
    sys.exit(0)

if __name__ == "__main__":
    scripts = ["fail2ban_endlessh.py", "rootkit_detection.py", "traffic_monitor.py", "ufw_hardening.py"]
    processes = []

    print("[INFO] Starting all security monitoring tools...")

    # Register signal handler for stopping processes
    signal.signal(signal.SIGINT, signal_handler)

    # Launch all scripts in parallel
    for script in scripts:
        process = multiprocessing.Process(target=run_script, args=(script,))
        process.start()
        processes.append(process)

    # Keep the main program running
    for process in processes:
        process.join()
