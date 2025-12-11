# vulners_client.py
import requests
import time
from typing import Dict, List, Any
import os
from dotenv import load_dotenv

load_dotenv()

class VulnersClient:
    def __init__(self):
        self.api_key = os.getenv('VULNERS_API_KEY')
        if not self.api_key:
            raise ValueError("VULNERS_API_KEY not found in environment variables")
        self.base_url = 'https://vulners.com/api/v3'
    
    def query_vulnerabilities(self, cve_list: List[str]) -> Dict[str, Any]:
        """Query Vulners for vulnerability details"""
        try:
            results = {}
            for cve_id in cve_list[:10]:  # Limit requests
                result = self._query_cve(cve_id)
                if result:
                    results[cve_id] = result
                time.sleep(0.5)  # Rate limiting
            
            return {
                'success': True, 
                'data': results
            }
        except Exception as e:
            return {
                'success': False, 
                'error': str(e), 
                'data': {}
            }
    
    def _query_cve(self, cve_id: str) -> Dict[str, Any]:
        """Query individual CVE from Vulners"""
        try:
            url = f"{self.base_url}/search/lucene/"
            params = {
                'query': f'cveId:{cve_id}',
                'apiKey': self.api_key
            }
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return self._format_vulners_response(data, cve_id)
        except Exception as e:
            print(f"Error querying {cve_id}: {e}")
        
        return None
    
    def _format_vulners_response(self, data: Dict, cve_id: str) -> Dict[str, Any]:
        """Format Vulners API response"""
        if not data.get('data', {}).get('search'):
            return {'error': 'No data found'}
        
        items = data['data']['search']
        if not items:
            return {'error': 'CVE not found'}
        
        item = items[0]
        cvss = item.get('cvss', {})
        
        return {
            'title': item.get('title', ''),
            'description': item.get('description', ''),
            'cvss_score': cvss.get('score', 0),
            'cvss_vector': cvss.get('vector', ''),
            'severity': cvss.get('severity', 'MEDIUM'),
            'published': item.get('published', ''),
            'modified': item.get('modified', ''),
            'references': item.get('references', []),
            'cwe_list': item.get('cwe', []),
            'exploit_count': item.get('exploitCount', 0),
            'patch_count': item.get('patchCount', 0)
        }