# virustotal_client.py
import requests
from typing import Dict, Any
import os
from dotenv import load_dotenv

load_dotenv()

class VirusTotalClient:
    def __init__(self):
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if not self.api_key:
            raise ValueError("VIRUSTOTAL_API_KEY not found in environment variables")
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.headers = {'x-apikey': self.api_key}
    
    def query_ip(self, ip_address: str) -> Dict[str, Any]:
        """Query VirusTotal for IP analysis"""
        try:
            url = f"{self.base_url}/ip_addresses/{ip_address}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'success': True,
                    'data': {
                        'ip_analysis': self._format_analysis(data)
                    }
                }
            return {
                'success': False, 
                'error': f'HTTP {response.status_code}', 
                'data': {}
            }
        except Exception as e:
            return {
                'success': False, 
                'error': str(e), 
                'data': {}
            }
    
    def _format_analysis(self, data: Dict) -> Dict[str, Any]:
        """Format VirusTotal analysis data"""
        last_analysis_stats = data.get('last_analysis_stats', {})
        
        return {
            'malicious': last_analysis_stats.get('malicious', 0),
            'suspicious': last_analysis_stats.get('suspicious', 0),
            'undetected': last_analysis_stats.get('undetected', 0),
            'harmless': last_analysis_stats.get('harmless', 0),
            'reputation': data.get('reputation', 0),
            'last_analysis_stats': last_analysis_stats,
            'country': data.get('country', 'Unknown'),
            'asn': data.get('asn', 'Unknown')
        }