#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Function to print status messages
print_status() {
    echo -e "${GREEN}[+] $1${NC}"
}

# Function to print error messages
print_error() {
    echo -e "${RED}[-] $1${NC}"
}

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run as root"
    exit 1
fi

# Update package lists
print_status "Updating package lists..."
apt-get update

# Install Python and pip
print_status "Installing Python and pip..."
apt-get install -y python3 python3-pip

# Install MongoDB
print_status "Installing MongoDB..."
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | apt-key add -
echo "deb http://repo.mongodb.org/apt/debian buster/mongodb-org/6.0 main" | tee /etc/apt/sources.list.d/mongodb-org-6.0.list
apt-get update
apt-get install -y mongodb-org
systemctl start mongod
systemctl enable mongod

# Install Nmap
print_status "Installing Nmap..."
apt-get install -y nmap

# Install Zeek
print_status "Installing Zeek..."
apt-get install -y zeek
echo 'export PATH=$PATH:/opt/zeek/bin' >> ~/.bashrc

# Install Suricata
print_status "Installing Suricata..."
apt-get install -y suricata
suricata-update

# Install Python packages
print_status "Installing Python packages..."
pip3 install flask
pip3 install pymongo
pip3 install google-generativeai
pip3 install secure-smtplib
pip3 install python-dotenv

# Create log directory
print_status "Creating log directory..."
mkdir -p /var/log/security_monitoring
chmod 755 /var/log/security_monitoring

# Verify installations
print_status "Verifying installations..."
python3 --version
mongo --version
nmap --version
zeek --version
suricata --version

print_status "Setup complete! Please source ~/.bashrc or restart your terminal."

# Check services status
print_status "Checking service status..."
systemctl status mongod | grep Active
systemctl status suricata | grep Active

# Create environment file
print_status "Creating .env file template..."
cat > .env << EOL
GOOGLE_API_KEY=your_api_key_here
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
ALERT_EMAIL=recipient@email.com
EOL

print_status "Don't forget to update the .env file with your credentials!"