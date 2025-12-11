# vulners_client.py
import requests
from typing import Dict, List, Any
import os
from dotenv import load_dotenv

load_dotenv()

class VulnersClient:
    def __init__(self):
        self.api_key = os.getenv('VULNERS_API_KEY', 'demo_key')
        self.base_url = 'https://vulners.com/api/v3'
        self.demo_mode = self.api_key == 'demo_key'
    
    def query_vulnerabilities(self, cve_list: List[str]) -> Dict[str, Any]:
        """Query Vulners for vulnerability details"""
        if self.demo_mode or not cve_list:
            return self._demo_response(cve_list[:3] if cve_list else [])
        
        try:
            results = {}
            for cve_id in cve_list[:10]:  # Limit requests
                result = self._query_cve(cve_id)
                if result:
                    results[cve_id] = result
                time.sleep(0.5)  # Rate limiting
            
            return {'success': True, 'data': results}
        except Exception as e:
            return {'success': False, 'error': str(e), 'data': {}}
    
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
    
    def _demo_response(self, cve_list: List[str]) -> Dict[str, Any]:
        """Demo response for Vulners"""
        demo_data = {
            'CVE-2021-44228': {
                'title': 'Apache Log4j2 Remote Code Execution',
                'description': 'Remote code execution in Log4j2',
                'cvss_score': 10.0,
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
                'severity': 'CRITICAL',
                'published': '2021-12-10T20:15:00Z',
                'exploit_count': 15,
                'patch_count': 3
            },
            'CVE-2022-22965': {
                'title': 'Spring Framework RCE',
                'description': 'Spring Framework remote code execution',
                'cvss_score': 9.8,
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'severity': 'CRITICAL',
                'published': '2022-03-31T19:15:00Z',
                'exploit_count': 8,
                'patch_count': 2
            }
        }
        
        results = {}
        for cve in cve_list:
            if cve in demo_data:
                results[cve] = demo_data[cve]
            else:
                results[cve] = {
                    'title': f'Demo data for {cve}',
                    'cvss_score': 7.5,
                    'severity': 'HIGH'
                }
        
        return {'success': True, 'data': results}