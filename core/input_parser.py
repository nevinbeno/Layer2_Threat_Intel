import json
import re

class InputParser:
    def parse(self, file_path: str) -> dict:
        with open(file_path, "r") as f:
            data = json.load(f)

        # Check if this is the PDF-like format (from your example)
        if "assets" in data:
            return self._parse_pdf_format(data)
        else:
            return self._parse_standard_format(data)
    
    def _parse_standard_format(self, data: dict) -> dict:
        """Parse the standard format your code was originally expecting"""
        return {
            "asset": data.get("asset", {}),
            "vulnerabilities": [
                {
                    "cve": v.get("cve"),
                    "severity": v.get("severity"),
                    "cvss": v.get("cvss_score") or v.get("cvss"),
                    "service": v.get("service")
                }
                for v in data.get("vulnerabilities", [])
            ]
        }
    
    def _parse_pdf_format(self, data: dict) -> dict:
        """Parse the PDF-like format from your example"""
        vulnerabilities = []
        
        # Extract asset info
        asset_info = {}
        if "assets" in data and len(data["assets"]) > 0:
            asset = data["assets"][0]
            asset_info = {
                "ip": asset.get("ip", ""),
                "hostname": asset.get("hostname", ""),
                "state": asset.get("state", "")
            }
        
        # Extract vulnerabilities from open ports
        for asset in data.get("assets", []):
            for port_info in asset.get("open_ports", []):
                cve_data = port_info.get("cve")
                
                # Skip if no CVE data
                if not cve_data or cve_data.get("id") in ["N/A", None]:
                    continue
                
                # Extract CVE ID - handle different field names
                cve_id = None
                if "id" in cve_data:
                    cve_id = cve_data.get("id")
                elif "cve" in cve_data:
                    cve_id = cve_data.get("cve")
                
                # Skip if still no valid CVE
                if not cve_id or cve_id == "N/A":
                    continue
                
                # Clean up CVE ID format
                if cve_id.startswith("CVE-"):
                    cve_id = cve_id.strip()
                
                vulnerability = {
                    "cve": cve_id,
                    "severity": cve_data.get("severity", "UNKNOWN"),
                    "cvss": cve_data.get("cvss") or cve_data.get("cvss_score"),
                    "service": port_info.get("service", ""),
                    "port": port_info.get("port_no"),
                    "product": port_info.get("product", "")
                }
                
                vulnerabilities.append(vulnerability)
        
        return {
            "asset": asset_info,
            "vulnerabilities": vulnerabilities
        }