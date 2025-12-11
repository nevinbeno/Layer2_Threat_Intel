# cisa_kev_client.py
import requests
from typing import Dict, List, Any

class CISAKEVClient:
    def __init__(self):
        self.base_url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    
    def query_kev(self) -> Dict[str, Any]:
        """Query CISA Known Exploited Vulnerabilities catalog"""
        try:
            response = requests.get(self.base_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return self._process_kev_data(data)
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
    
    def _process_kev_data(self, data: Dict) -> Dict[str, Any]:
        """Process KEV data into structured format"""
        vulnerabilities = data.get('vulnerabilities', [])
        
        kev_dict = {}
        for vuln in vulnerabilities:
            cve_id = vuln.get('cveID')
            kev_dict[cve_id] = {
                'date_added': vuln.get('dateAdded'),
                'short_description': vuln.get('shortDescription'),
                'required_action': vuln.get('requiredAction'),
                'due_date': vuln.get('dueDate'),
                'known_ransomware_use': vuln.get('knownRansomwareCampaignUse', False),
                'notes': vuln.get('notes', ''),
                'vendor': vuln.get('vendorProject', '')
            }
        
        return {
            'success': True,
            'data': kev_dict,
            'total_count': len(vulnerabilities),
            'catalog_version': data.get('catalogVersion', ''),
            'date_released': data.get('dateReleased', '')
        }
    
    def check_cves_in_kev(self, cve_list: List[str], kev_data: Dict) -> Dict[str, Any]:
        """Check which CVEs from list are in KEV catalog"""
        kev_catalog = kev_data.get('data', {})
        matches = {}
        
        for cve in cve_list:
            if cve in kev_catalog:
                matches[cve] = kev_catalog[cve]
        
        return {
            'matches': matches,
            'match_count': len(matches),
            'total_checked': len(cve_list),
            'percentage': round(len(matches) / len(cve_list) * 100, 1) if cve_list else 0
        }