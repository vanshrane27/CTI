import subprocess

def setup_ufw():
    """Set up and harden UFW with security-focused rules."""
    print("Setting up and hardening UFW...")

    # Reset UFW to default settings
    subprocess.run(["sudo", "ufw", "reset"], check=True)
    print("UFW reset to default settings.")

    # Default deny incoming, allow outgoing
    subprocess.run(["sudo", "ufw", "default", "deny", "incoming"], check=True)
    subprocess.run(["sudo", "ufw", "default", "allow", "outgoing"], check=True)
    print("Default policies set: deny incoming, allow outgoing.")

    # Allow SSH (use a non-standard port if possible for added security)
    ssh_port = 2222  # Change this to your SSH port
    subprocess.run(["sudo", "ufw", "allow", f"{ssh_port}/tcp"], check=True)
    print(f"Allowed SSH on port {ssh_port}.")

    # Allow specific application ports (adjust as needed)
    allowed_ports = [80, 443]  # HTTP and HTTPS
    for port in allowed_ports:
        subprocess.run(["sudo", "ufw", "allow", f"{port}/tcp"], check=True)
        print(f"Allowed traffic on port {port} (TCP).")

    # Enable rate limiting to prevent brute-force attacks
    subprocess.run(["sudo", "ufw", "limit", f"{ssh_port}/tcp"], check=True)
    print(f"Rate limiting enabled for SSH on port {ssh_port}.")

    # Block ICMP (ping requests) for stealth
    with open("/etc/ufw/before.rules", "r") as file:
        before_rules = file.readlines()

    with open("/etc/ufw/before.rules", "w") as file:
        for line in before_rules:
            if line.strip() == "-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT":
                # Comment out the line that allows ICMP requests
                file.write(f"# {line}")
            else:
                file.write(line)
    print("Blocked ICMP ping requests for stealth.")

    # Enable logging (level: low for concise output, can be set to medium or high)
    subprocess.run(["sudo", "ufw", "logging", "low"], check=True)
    print("Logging enabled (low level).")

    # Enable UFW
    subprocess.run(["sudo", "ufw", "enable"], check=True)
    print("UFW enabled and hardened successfully.")

def check_ufw_status():
    """Check the current status of UFW."""
    print("Checking UFW status...")
    subprocess.run(["sudo", "ufw", "status", "verbose"], check=True)

def main():
    try:
        print("Starting UFW hardening script...")
        setup_ufw()
        check_ufw_status()
        print("UFW hardening completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while executing a command: {e}")
    except Exception as ex:
        print(f"Unexpected error: {ex}")

if __name__ == "__main__":
    main()
