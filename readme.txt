Make it executable:
chmod +x setup.sh

Run the script:
sudo ./setup.sh

pip install watchdog
pip install pyyaml

API_KEY=your-secret-key-here
MONGO_URI=mongodb://localhost:27017
# Get recent threats
curl -H "X-API-Key: your-secret-key" http://localhost:5000/api/v1/threats

# Get high severity alerts
curl -H "X-API-Key: your-secret-key" http://localhost:5000/api/v1/alerts?severity=high

pip install tkinter matplotlib requests

