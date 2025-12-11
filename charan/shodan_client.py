# shodan_client.py
import requests
from datetime import datetime
from typing import Dict, Any
import os
from dotenv import load_dotenv

load_dotenv()

class ShodanClient:
    def __init__(self):
        self.api_key = os.getenv('SHODAN_API_KEY')
        if not self.api_key:
            raise ValueError("SHODAN_API_KEY not found in environment variables")
        self.base_url = 'https://api.shodan.io'
    
    def query_ip(self, ip_address: str) -> Dict[str, Any]:
        """Query Shodan for IP intelligence"""
        try:
            url = f"{self.base_url}/shodan/host/{ip_address}"
            params = {'key': self.api_key}
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return self._format_response(data)
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
    
    def _format_response(self, data: Dict) -> Dict[str, Any]:
        """Format Shodan response"""
        return {
            'success': True,
            'data': {
                'ip': data.get('ip_str'),
                'ports': data.get('ports', []),
                'vulnerabilities': list(data.get('vulns', {}).keys()),
                'hostnames': data.get('hostnames', []),
                'org': data.get('org', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'location': data.get('location', {}),
                'last_update': data.get('last_update', '')
            }
        }