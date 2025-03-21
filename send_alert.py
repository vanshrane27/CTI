import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, Optional
import os
from dotenv import load_dotenv

class SecurityAlert:
    def __init__(self):
        """Initialize email alert system"""
        load_dotenv()
        
        # Email configuration
        self.smtp_config = {
            'server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
            'port': int(os.getenv('SMTP_PORT', 587)),
            'username': os.getenv('SMTP_USERNAME'),
            'password': os.getenv('SMTP_PASSWORD'),
            'recipient': os.getenv('ALERT_EMAIL')
        }
        
        # Validate configuration
        if not all(self.smtp_config.values()):
            raise ValueError("Email configuration incomplete. Check .env file.")
            
        # HTML email template
        self.email_template = """
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: #cc0000;">⚠️ Security Alert</h2>
            <hr>
            <h3>Threat Details:</h3>
            <table style="border-collapse: collapse; width: 100%;">
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;"><strong>Type:</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{type}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;"><strong>Severity:</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd; color: {severity_color};">{severity}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;"><strong>Time Detected:</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{timestamp}</td>
                </tr>
            </table>
            
            <h3>Details:</h3>
            <p>{details}</p>
            
            <h3>Recommended Actions:</h3>
            <ul>
                {mitigation_steps}
            </ul>
            
            <p style="color: #666; font-size: 12px;">
                This is an automated alert from your security monitoring system.
            </p>
        </body>
        </html>
        """

    def get_mitigation_steps(self, alert_type: str) -> list:
        """Get recommended mitigation steps based on alert type"""
        mitigations = {
            'high_risk_cve': [
                "Update affected systems immediately",
                "Apply available security patches",
                "Monitor systems for exploitation attempts",
                "Consider temporary system isolation if patch unavailable"
            ],
            'brute_force': [
                "Block offending IP addresses",
                "Review authentication logs",
                "Enable account lockout policies",
                "Consider implementing 2FA"
            ],
            'port_scanning': [
                "Review firewall rules",
                "Block suspicious IP addresses",
                "Enable IDS alerts for scan attempts",
                "Consider implementing port knocking"
            ]
        }
        return mitigations.get(alert_type, ["Review system logs", "Contact security team"])

    def send_alert(self, alert_data: Dict) -> bool:
        """Send email alert for security threat"""
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"SECURITY ALERT: {alert_data['type']}"
            msg['From'] = self.smtp_config['username']
            msg['To'] = self.smtp_config['recipient']
            
            # Prepare email content
            severity_colors = {
                'HIGH': '#cc0000',
                'MEDIUM': '#ff9900',
                'LOW': '#ffcc00'
            }
            
            # Generate mitigation steps HTML
            mitigation_html = ""
            for step in self.get_mitigation_steps(alert_data['type']):
                mitigation_html += f"<li>{step}</li>"
            
            # Format email body
            html_content = self.email_template.format(
                type=alert_data['type'],
                severity=alert_data['severity'],
                severity_color=severity_colors.get(alert_data['severity'], '#000000'),
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                details=alert_data['details'],
                mitigation_steps=mitigation_html
            )
            
            msg.attach(MIMEText(html_content, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port']) as server:
                server.starttls(context=ssl.create_default_context())
                server.login(self.smtp_config['username'], self.smtp_config['password'])
                server.send_message(msg)
                
            print(f"[+] Alert email sent successfully to {self.smtp_config['recipient']}")
            return True
            
        except Exception as e:
            print(f"[-] Error sending alert email: {str(e)}")
            return False

def main():
    # Test alert
    test_alert = {
        'type': 'high_risk_cve',
        'severity': 'HIGH',
        'details': 'Critical vulnerability detected in production system'
    }
    
    try:
        alert_system = SecurityAlert()
        alert_system.send_alert(test_alert)
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()