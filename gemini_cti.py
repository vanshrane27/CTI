import os
import json
import google.generativeai as genai
from datetime import datetime
from typing import Dict, List, Optional
from dotenv import load_dotenv

class ThreatIntelligence:
    def __init__(self):
        """Initialize Gemini API with credentials"""
        load_dotenv()
        api_key = os.getenv('GOOGLE_API_KEY')
        if not api_key:
            raise ValueError("Google API key not found in environment variables")
            
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro')
        
    def fetch_threat_intel(self) -> Dict:
        """Fetch latest threat intelligence from Gemini API"""
        try:
            prompt = """
            Act as a cybersecurity analyst and provide the following information:
            1. Latest emerging cyber threats in the last 24 hours
            2. Recent critical CVEs with CVSS score > 7.0
            3. Active attack vectors being exploited
            4. Recommended mitigation strategies
            
            Format the response as a detailed JSON structure.
            """
            
            response = self.model.generate_content(prompt)
            
            # Parse and structure the response
            threat_data = json.loads(response.text)
            
            # Add metadata
            enriched_data = {
                "timestamp": datetime.now().isoformat(),
                "source": "Google Gemini AI",
                "data": threat_data,
                "metadata": {
                    "query_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "confidence_score": self._calculate_confidence(threat_data)
                }
            }
            
            return enriched_data
            
        except Exception as e:
            return {
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
                "status": "failed"
            }
    
    def _calculate_confidence(self, data: Dict) -> float:
        """Calculate confidence score based on threat data completeness"""
        score = 0
        required_fields = ['threats', 'cves', 'attack_vectors', 'mitigations']
        
        for field in required_fields:
            if field in data and data[field]:
                score += 0.25
                
        return round(score, 2)
    
    def get_specific_cve(self, cve_id: str) -> Optional[Dict]:
        """Fetch details for a specific CVE"""
        try:
            prompt = f"""
            Provide detailed information about {cve_id} including:
            1. CVSS score
            2. Affected systems
            3. Exploitation methods
            4. Patch availability
            5. Mitigation steps
            
            Format the response as JSON.
            """
            
            response = self.model.generate_content(prompt)
            return json.loads(response.text)
            
        except Exception as e:
            return None

def main():
    try:
        # Initialize threat intelligence
        ti = ThreatIntelligence()
        
        # Fetch latest threat intel
        threat_data = ti.fetch_threat_intel()
        
        # Save to file with timestamp
        filename = f"threat_intel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(threat_data, f, indent=4)
            
        print(f"Threat intelligence saved to {filename}")
        
        # Optional: Get specific CVE details
        cve_details = ti.get_specific_cve("CVE-2024-1234")
        if cve_details:
            print("\nSpecific CVE Details:")
            print(json.dumps(cve_details, indent=4))
            
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()