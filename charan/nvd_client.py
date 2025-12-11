# nvd_client.py
import requests
import time
from typing import Dict, List, Any
from collections import defaultdict

class NVDClient:
    def __init__(self):
        self.base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    
    def query_cves(self, cve_list: List[str]) -> Dict[str, Any]:
        """Query NVD for CVE details"""
        results = {}
        
        for cve_id in cve_list[:10]:  # Increased limit for real use
            try:
                result = self._query_single_cve(cve_id)
                if result:
                    results[cve_id] = result
                time.sleep(0.6)  # NVD rate limiting (max 5 requests per 3 seconds)
            except Exception as e:
                results[cve_id] = {'error': str(e)}
        
        return {'success': True, 'data': results}
    
    def _query_single_cve(self, cve_id: str) -> Dict[str, Any]:
        """Query a single CVE from NVD"""
        try:
            url = f"{self.base_url}?cveId={cve_id}"
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                return self._process_cve_data(data, cve_id)
            else:
                return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _process_cve_data(self, data: Dict, cve_id: str) -> Dict[str, Any]:
        """Extract relevant CVE data from NVD response"""
        if not data.get('vulnerabilities'):
            return {'error': 'CVE not found'}
        
        cve_data = data['vulnerabilities'][0]['cve']
        metrics = self._extract_cvss_metrics(cve_data)
        cwes = self._extract_cwes(cve_data)
        
        return {
            'cve_id': cve_id,
            'description': cve_data.get('descriptions', [{}])[0].get('value', 'No description'),
            'published_date': cve_data.get('published', ''),
            'last_modified': cve_data.get('lastModified', ''),
            'cvss_metrics': metrics,
            'severity': self._get_severity_level(metrics.get('baseScore', 0)),
            'cwe_list': cwes,
            'references': [ref.get('url') for ref in cve_data.get('references', [])],
            'vendor_comments': cve_data.get('vendorComments', [])
        }
    
    def _extract_cvss_metrics(self, cve_data: Dict) -> Dict[str, Any]:
        """Extract CVSS metrics from CVE data"""
        metrics = {}
        
        if 'metrics' in cve_data:
            # Try CVSS v3.1 first
            if 'cvssMetricV31' in cve_data['metrics']:
                cvss_data = cve_data['metrics']['cvssMetricV31'][0]['cvssData']
                metrics = {
                    'version': '3.1',
                    'baseScore': cvss_data.get('baseScore', 0),
                    'baseSeverity': cvss_data.get('baseSeverity', 'MEDIUM'),
                    'vectorString': cvss_data.get('vectorString', ''),
                    'attackVector': cvss_data.get('attackVector', ''),
                    'attackComplexity': cvss_data.get('attackComplexity', ''),
                    'privilegesRequired': cvss_data.get('privilegesRequired', ''),
                    'userInteraction': cvss_data.get('userInteraction', ''),
                    'scope': cvss_data.get('scope', ''),
                    'confidentialityImpact': cvss_data.get('confidentialityImpact', ''),
                    'integrityImpact': cvss_data.get('integrityImpact', ''),
                    'availabilityImpact': cvss_data.get('availabilityImpact', '')
                }
            # Fall back to CVSS v2
            elif 'cvssMetricV2' in cve_data['metrics']:
                cvss_data = cve_data['metrics']['cvssMetricV2'][0]['cvssData']
                metrics = {
                    'version': '2.0',
                    'baseScore': cvss_data.get('baseScore', 0),
                    'vectorString': cvss_data.get('vectorString', ''),
                    'accessVector': cvss_data.get('accessVector', ''),
                    'accessComplexity': cvss_data.get('accessComplexity', ''),
                    'authentication': cvss_data.get('authentication', ''),
                    'confidentialityImpact': cvss_data.get('confidentialityImpact', ''),
                    'integrityImpact': cvss_data.get('integrityImpact', ''),
                    'availabilityImpact': cvss_data.get('availabilityImpact', '')
                }
        
        return metrics
    
    def _extract_cwes(self, cve_data: Dict) -> List[str]:
        """Extract CWE IDs from CVE data"""
        cwes = []
        for problem_type in cve_data.get('weaknesses', []):
            for desc in problem_type.get('description', []):
                if desc.get('value', '').startswith('CWE-'):
                    cwes.append(desc['value'])
        return cwes
    
    def _get_severity_level(self, score: float) -> str:
        """Convert CVSS score to severity level"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score > 0:
            return 'LOW'
        return 'INFO'