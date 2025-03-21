import nmap
import json
import argparse
from datetime import datetime
from typing import Dict, List, Optional
import os

class NmapScanner:
    def __init__(self):
        """Initialize Nmap scanner"""
        self.scanner = nmap.PortScanner()
        self.output_dir = "scan_results"
        os.makedirs(self.output_dir, exist_ok=True)

    def run_scan(self, target_ip: str, scan_type: str = "-sV") -> Dict:
        """
        Execute Nmap scan on target IP
        Args:
            target_ip: IP address to scan
            scan_type: Nmap scan type (default: -sV for service detection)
        """
        try:
            print(f"[*] Starting scan on {target_ip}")
            self.scanner.scan(target_ip, arguments=scan_type)
            
            scan_results = {
                "scan_info": {
                    "target": target_ip,
                    "timestamp": datetime.now().isoformat(),
                    "scan_type": scan_type
                },
                "results": self._parse_results(target_ip)
            }

            # Save results
            self._save_results(scan_results, target_ip)
            return scan_results

        except Exception as e:
            error_result = {
                "error": str(e),
                "target": target_ip,
                "timestamp": datetime.now().isoformat()
            }
            self._save_results(error_result, target_ip)
            return error_result

    def _parse_results(self, target_ip: str) -> Dict:
        """Parse Nmap scan results"""
        if target_ip not in self.scanner.all_hosts():
            return {"status": "No results"}

        host_data = self.scanner[target_ip]
        parsed_data = {
            "status": host_data.state(),
            "open_ports": [],
            "services": [],
            "os_match": host_data.get("osmatch", "Unknown"),
            "vulnerabilities": []
        }

        # Parse port and service information
        for proto in host_data.all_protocols():
            ports = host_data[proto].keys()
            for port in ports:
                port_info = host_data[proto][port]
                if port_info["state"] == "open":
                    parsed_data["open_ports"].append(port)
                    service_info = {
                        "port": port,
                        "service": port_info.get("name", "unknown"),
                        "version": port_info.get("version", "unknown"),
                        "product": port_info.get("product", "unknown")
                    }
                    parsed_data["services"].append(service_info)

                    # Check for potential vulnerabilities
                    if "script" in port_info:
                        for script_name, output in port_info["script"].items():
                            if "VULNERABLE" in output:
                                parsed_data["vulnerabilities"].append({
                                    "port": port,
                                    "script": script_name,
                                    "details": output
                                })

        return parsed_data

    def _save_results(self, results: Dict, target_ip: str) -> None:
        """Save scan results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/nmap_scan_{target_ip}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"[+] Results saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description='Nmap Scanner')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('--type', default='-sV', help='Scan type (default: -sV)')
    args = parser.parse_args()

    scanner = NmapScanner()
    results = scanner.run_scan(args.target, args.type)
    print("\nScan Summary:")
    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()