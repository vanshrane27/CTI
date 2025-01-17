import os
import subprocess

FAIL2BAN_JAIL_LOCAL = "/etc/fail2ban/jail.local"
ENDLESSH_CONFIG_PATH = "/etc/endlessh/config"
BANNED_IP_LOG = "/var/log/fail2ban_banned_ips.txt"

def configure_endlessh(port=2222, delay=15000, max_clients=8192):
    """Configure Endlessh to trap SSH brute-force attempts."""
    print("Configuring Endlessh...")
    config_content = f"""
# Endlessh configuration
Port {port}
Delay {delay}
MaxLineLength 32
MaxClients {max_clients}
LogLevel 1
"""
    with open(ENDLESSH_CONFIG_PATH, "w") as config_file:
        config_file.write(config_content)
    print(f"Endlessh configuration written to {ENDLESSH_CONFIG_PATH}")

def configure_fail2ban_for_endlessh():
    """
    Configure Fail2Ban to monitor Endlessh logs and ban IPs attempting brute force.
    """
    print("Configuring Fail2Ban for Endlessh...")
    jail_config = f"""
[endlessh]
enabled = true
port = 2222
logpath = /var/log/endlessh.log
maxretry = 5
findtime = 10m
bantime = 1h
"""
    with open(FAIL2BAN_JAIL_LOCAL, "a") as jail_file:
        jail_file.write(jail_config)
    print(f"Fail2Ban jail configuration updated for Endlessh at {FAIL2BAN_JAIL_LOCAL}")

def restart_services():
    """Restart Fail2Ban and Endlessh services to apply changes."""
    print("Restarting Fail2Ban and Endlessh services...")
    subprocess.run(["sudo", "systemctl", "restart", "fail2ban"], check=True)
    subprocess.run(["sudo", "systemctl", "restart", "endlessh"], check=True)
    print("Services restarted successfully.")

def log_banned_ips():
    """Monitor Fail2Ban logs and log banned IPs to a text file."""
    fail2ban_log_path = "/var/log/fail2ban.log"
    print(f"Monitoring {fail2ban_log_path} for banned IPs...")
    if not os.path.exists(BANNED_IP_LOG):
        open(BANNED_IP_LOG, "w").close()  # Create the banned IP log file if it doesn't exist

    with open(fail2ban_log_path, "r") as log_file:
        log_file.seek(0, os.SEEK_END)  # Start reading from the end of the log
        while True:
            line = log_file.readline()
            if not line:
                continue
            if "Ban" in line:
                ip = line.split()[-1]  # Extract the banned IP address
                with open(BANNED_IP_LOG, "a") as banned_log:
                    banned_log.write(f"{ip}\n")
                print(f"Banned IP logged: {ip}")

def main():
    try:
        print("Starting Endlessh and Fail2Ban integration...")
        # Configure Endlessh
        configure_endlessh(port=2222, delay=15000, max_clients=8192)

        # Configure Fail2Ban for Endlessh
        configure_fail2ban_for_endlessh()

        # Restart services
        restart_services()

        # Monitor banned IPs (Optional: comment out if not needed)
        # log_banned_ips()

        print("Fail2Ban and Endlessh integration completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while executing a command: {e}")
    except Exception as ex:
        print(f"Unexpected error: {ex}")

if __name__ == "__main__":
    main()
