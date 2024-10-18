import os
import time
import re
import subprocess
import openai

# Set up OpenAI API key
openai.api_key = os.getenv('sk-BQqA0L0930-GLxl4K1TbDKh2mnHcobmjfm9j_CpRTfT3BlbkFJrcavrIK0gya3JvKMt4lC4HOhLgL-k-rJLjaiIQGoIA')

UFW_LOG_PATH = "/var/log/ufw.log"
ALERT_THRESHOLD = 10  # Customize based on your security level
LOG_MONITOR_INTERVAL = 60  # Check logs every 60 seconds


def check_ufw_status():
    """Check if UFW is active, and start it if not."""
    status = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True)
    if "inactive" in status.stdout:
        print("UFW is not running. Starting UFW...")
        subprocess.run(['sudo', 'ufw', 'enable'], check=True)
        print("UFW has been started.")
    else:
        print("UFW is already running.")


def get_log_tail(log_path, lines=50):
    """Reads the last 'lines' lines from a log file."""
    with open(log_path, 'rb') as f:
        f.seek(0, os.SEEK_END)
        buffer_size = 8192
        buffer = b''
        while f.tell() > 0 and lines > 0:
            to_read = min(buffer_size, f.tell())
            f.seek(-to_read, os.SEEK_CUR)
            buffer = f.read(to_read) + buffer
            f.seek(-to_read, os.SEEK_CUR)
            lines -= buffer.count(b'\n')
        return buffer.decode('utf-8').splitlines()[-lines:]


def analyze_logs(log_entries):
    """Send log entries to OpenAI API to check for suspicious patterns."""
    prompt = (
        "Analyze these UFW logs and identify any suspicious activity. "
        "Provide potential reasons and security solutions: \n" + '\n'.join(log_entries)
    )

    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=prompt,
        max_tokens=200
    )

    return response.choices[0].text.strip()


def system_alert(message):
    """Trigger a system notification."""
    subprocess.run(['notify-send', 'UFW Suspicious Activity Alert', message], check=True)


def monitor_ufw_logs():
    print("Monitoring UFW logs for suspicious activity...")
    while True:
        try:
            # Fetch the last 50 lines from UFW log
            log_entries = get_log_tail(UFW_LOG_PATH)

            # Parse log for potential threats (using a basic regex)
            suspicious_logs = [line for line in log_entries if re.search(r'(DROPPED|REJECT)', line)]

            if len(suspicious_logs) > ALERT_THRESHOLD:
                print(f"Suspicious activity detected! {len(suspicious_logs)} potential threats.")

                analysis = analyze_logs(suspicious_logs)
                print("AI Analysis and Recommendations:")
                print(analysis)

                system_alert(f"Suspicious activity detected: {len(suspicious_logs)} potential threats.\nCheck logs for details.")

            time.sleep(LOG_MONITOR_INTERVAL)

        except Exception as e:
            print(f"Error occurred: {e}")
            time.sleep(LOG_MONITOR_INTERVAL)


if __name__ == "__main__":
    check_ufw_status()

    monitor_ufw_logs()
