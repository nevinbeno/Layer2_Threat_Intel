import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import os
from dotenv import load_dotenv
from collections import defaultdict

# Load API keys from environment
load_dotenv()

class ThreatIntelligenceEngine:
    def __init__(self):
        # API Keys
        self.shodan_api_key = os.getenv('SHODAN_API_KEY', 'demo_key')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', 'demo_key')
        self.vulners_api_key = os.getenv('VULNERS_API_KEY', 'demo_key')
        
        # Demo mode flag
        self.demo_mode = any(key == 'demo_key' for key in 
                            [self.shodan_api_key, self.virustotal_api_key, self.vulners_api_key])
        
        # API Endpoints
        self.apis = {
            'shodan': 'https://api.shodan.io',
            'virustotal': 'https://www.virustotal.com/api/v3',
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'cisa_kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
        }
        
        # Headers
        self.headers = {
            'virustotal': {'x-apikey': self.virustotal_api_key}
        }

    def process_layer1_data(self, scan_data: Dict = None) -> Dict:
        """Process sample data from Layer 1 (Vulnerability Scanning)"""
        default_data = {
            "host": "192.168.1.10",
            "ip": "8.8.8.8",
            "ports": [
                {"port": 22, "service": "ssh", "state": "open", "version": "OpenSSH 8.2"},
                {"port": 80, "service": "http", "state": "open", "version": "nginx 1.18"},
                {"port": 443, "service": "https", "state": "open", "version": "Apache 2.4.49"}
            ],
            "vulnerabilities": [
                {"cve": "CVE-2021-44228", "description": "Log4Shell", "severity": "CRITICAL"},
                {"cve": "CVE-2022-22965", "description": "Spring4Shell", "severity": "CRITICAL"},
                {"cve": "CVE-2021-41617", "description": "SSH vulnerability", "severity": "HIGH"}
            ],
            "software": [
                {"name": "OpenSSH", "version": "8.2", "vendor": "OpenBSD"},
                {"name": "nginx", "version": "1.18.0", "vendor": "Nginx Inc."},
                {"name": "Apache", "version": "2.4.49", "vendor": "Apache Foundation"}
            ],
            "metadata": {
                "scan_timestamp": datetime.now().isoformat(),
                "scanner": "nmap_openvas",
                "asset_value": "critical"
            }
        }
        return scan_data if scan_data else default_data

    def query_shodan(self, ip_address: str) -> Dict:
        """Query Shodan for IP intelligence"""
        if self.demo_mode:
            return self._demo_shodan_response(ip_address)
        
        try:
            url = f"{self.apis['shodan']}/shodan/host/{ip_address}"
            params = {'key': self.shodan_api_key}
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
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
            return {'success': False, 'error': f'HTTP {response.status_code}', 'data': {}}
        except Exception as e:
            return {'success': False, 'error': str(e), 'data': {}}

    def _demo_shodan_response(self, ip_address: str) -> Dict:
        """Demo response for Shodan"""
        return {
            'success': True,
            'data': {
                'ip': ip_address,
                'ports': [22, 80, 443, 8080],
                'vulnerabilities': ['CVE-2021-44228', 'CVE-2022-22965'],
                'hostnames': [f'host-{ip_address.replace(".", "-")}.example.com'],
                'org': 'Demo Corporation',
                'isp': 'Demo ISP',
                'location': {'city': 'Demo City', 'country': 'Demo Country'},
                'last_update': datetime.now().isoformat()
            }
        }

    def query_virustotal(self, indicators: Dict) -> Dict:
        """Query VirusTotal for indicators"""
        if self.demo_mode:
            return self._demo_virustotal_response(indicators)
        
        try:
            headers = self.headers['virustotal']
            results = {}
            
            if 'ip' in indicators:
                url = f"{self.apis['virustotal']}/ip_addresses/{indicators['ip']}"
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    results['ip_analysis'] = response.json().get('data', {})
            
            return {'success': True, 'data': results}
        except Exception as e:
            return {'success': False, 'error': str(e), 'data': {}}

    def _demo_virustotal_response(self, indicators: Dict) -> Dict:
        """Demo response for VirusTotal"""
        return {
            'success': True,
            'data': {
                'ip_analysis': {
                    'malicious': 2,
                    'suspicious': 1,
                    'undetected': 45,
                    'harmless': 52,
                    'reputation': -5,
                    'last_analysis_stats': {
                        'malicious': 2,
                        'suspicious': 1,
                        'undetected': 45,
                        'harmless': 52
                    }
                }
            }
        }

    def query_nvd(self, cves: List[str]) -> Dict:
        """Query NVD for CVE details"""
        results = {}
        
        for cve_id in cves[:3]:  # Limit for demo
            if self.demo_mode:
                results[cve_id] = self._demo_nvd_response(cve_id)
            else:
                try:
                    url = f"{self.apis['nvd']}?cveId={cve_id}"
                    response = requests.get(url, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json()
                        if 'vulnerabilities' in data and data['vulnerabilities']:
                            cve_data = data['vulnerabilities'][0]['cve']
                            metrics = self._extract_cvss_metrics(cve_data)
                            
                            results[cve_id] = {
                                'description': cve_data.get('descriptions', [{}])[0].get('value', ''),
                                'published_date': cve_data.get('published', ''),
                                'cvss_metrics': metrics,
                                'severity': self._get_severity_level(metrics.get('baseScore', 0))
                            }
                    time.sleep(1)  # Rate limiting
                except Exception as e:
                    results[cve_id] = {'error': str(e)}
        
        return {'success': True, 'data': results}

    def _demo_nvd_response(self, cve_id: str) -> Dict:
        """Demo response for NVD"""
        demo_data = {
            'CVE-2021-44228': {
                'description': 'Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
                'published_date': '2021-12-10T20:15:00Z',
                'cvss_metrics': {'baseScore': 10.0, 'baseSeverity': 'CRITICAL'},
                'severity': 'CRITICAL'
            },
            'CVE-2022-22965': {
                'description': 'Spring Framework prior to versions 5.3.18 and 5.2.20 and corresponding older versions suffers from a remote code execution vulnerability.',
                'published_date': '2022-03-31T19:15:00Z',
                'cvss_metrics': {'baseScore': 9.8, 'baseSeverity': 'CRITICAL'},
                'severity': 'CRITICAL'
            },
            'CVE-2021-41617': {
                'description': 'sshd in OpenSSH 6.2 through 8.7 allows remote attackers to cause a denial of service.',
                'published_date': '2021-09-15T07:15:00Z',
                'cvss_metrics': {'baseScore': 7.5, 'baseSeverity': 'HIGH'},
                'severity': 'HIGH'
            }
        }
        return demo_data.get(cve_id, {'description': 'Unknown CVE', 'cvss_metrics': {'baseScore': 0}})

    def _extract_cvss_metrics(self, cve_data: Dict) -> Dict:
        """Extract CVSS metrics from NVD response"""
        metrics = {}
        if 'metrics' in cve_data:
            if 'cvssMetricV31' in cve_data['metrics']:
                metrics = cve_data['metrics']['cvssMetricV31'][0]['cvssData']
            elif 'cvssMetricV30' in cve_data['metrics']:
                metrics = cve_data['metrics']['cvssMetricV30'][0]['cvssData']
            elif 'cvssMetricV2' in cve_data['metrics']:
                metrics = cve_data['metrics']['cvssMetricV2'][0]['cvssData']
        return metrics

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

    def query_cisa_kev(self) -> Dict:
        """Query CISA Known Exploited Vulnerabilities"""
        try:
            response = requests.get(self.apis['cisa_kev'], timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                kev_dict = {}
                for vuln in vulnerabilities[:100]:
                    cve_id = vuln.get('cveID')
                    kev_dict[cve_id] = {
                        'date_added': vuln.get('dateAdded'),
                        'short_description': vuln.get('shortDescription'),
                        'required_action': vuln.get('requiredAction'),
                        'known_ransomware_use': vuln.get('knownRansomwareCampaignUse', False)
                    }
                
                return {'success': True, 'data': kev_dict, 'total_count': len(vulnerabilities)}
            return {'success': False, 'error': f'HTTP {response.status_code}', 'data': {}}
        except Exception as e:
            return {'success': False, 'error': str(e), 'data': {}}

    def generate_visual_analytics(self, threat_data: Dict) -> Dict:
        """Generate visual analytics from threat intelligence data"""
        visuals = {}
        
        # Extract NVD data safely
        nvd_data = threat_data.get('nvd_results', {}).get('data', {})
        
        # 1. CVE Severity Distribution
        severity_counts = defaultdict(int)
        for cve_id, details in nvd_data.items():
            if isinstance(details, dict):
                severity = details.get('severity', 'UNKNOWN')
                severity_counts[severity] += 1
        
        if severity_counts:
            total = sum(severity_counts.values())
            visuals['severity_distribution'] = {
                'type': 'pie_chart',
                'data': [
                    {'severity': k, 'count': v, 'percentage': round(v/total*100, 1)}
                    for k, v in severity_counts.items()
                ],
                'total': total
            }
        
        # 2. CVSS Score Distribution
        cvss_scores = []
        for cve_id, details in nvd_data.items():
            if isinstance(details, dict):
                score = details.get('cvss_metrics', {}).get('baseScore', 0)
                if score > 0:
                    cvss_scores.append({
                        'cve': cve_id,
                        'score': score,
                        'severity': details.get('severity', 'UNKNOWN')
                    })
        
        if cvss_scores:
            visuals['cvss_distribution'] = {
                'type': 'histogram',
                'data': cvss_scores,
                'average_score': round(sum(s['score'] for s in cvss_scores) / len(cvss_scores), 1),
                'max_score': max(s['score'] for s in cvss_scores) if cvss_scores else 0
            }
        
        # 3. KEV Status
        kev_data = threat_data.get('cisa_kev_results', {}).get('data', {})
        scan_cves = []
        if 'scan_data' in threat_data:
            vulnerabilities = threat_data['scan_data'].get('vulnerabilities', [])
            scan_cves = [v.get('cve') for v in vulnerabilities if isinstance(v, dict) and 'cve' in v]
        
        if kev_data and scan_cves:
            kev_cves = set(kev_data.keys())
            in_kev = len(set(scan_cves).intersection(kev_cves))
            not_in_kev = len(scan_cves) - in_kev
            
            visuals['kev_status'] = {
                'type': 'bar_chart',
                'data': {
                    'in_kev': in_kev,
                    'not_in_kev': not_in_kev
                },
                'percentage_in_kev': round(in_kev/len(scan_cves)*100, 1) if scan_cves else 0
            }
        
        # 4. Threat Timeline
        timeline_data = []
        for cve_id, details in nvd_data.items():
            if isinstance(details, dict) and details.get('published_date'):
                try:
                    date_str = details['published_date'].split('T')[0]
                    timeline_data.append({
                        'date': date_str,
                        'cve': cve_id,
                        'score': details.get('cvss_metrics', {}).get('baseScore', 0)
                    })
                except:
                    continue
        
        if timeline_data:
            visuals['timeline'] = {
                'type': 'timeline',
                'data': sorted(timeline_data, key=lambda x: x['date']),
                'date_range': {
                    'start': min(t['date'] for t in timeline_data),
                    'end': max(t['date'] for t in timeline_data)
                }
            }
        
        # 5. Shodan Exposure Summary
        shodan_data = threat_data.get('shodan_results', {}).get('data', {})
        if shodan_data:
            visuals['shodan_summary'] = {
                'type': 'exposure_summary',
                'open_ports': shodan_data.get('ports', []),
                'vulnerabilities_found': shodan_data.get('vulnerabilities', []),
                'hostnames': shodan_data.get('hostnames', []),
                'location': shodan_data.get('location', {})
            }
        
        return visuals

    def generate_summary(self, results: Dict, visuals: Dict) -> Dict:
        """Generate executive summary"""
        
        # Get vulnerabilities from scan data
        scan_data = results.get('scan_data', {})
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # Get CVE IDs from vulnerabilities list
        scan_cves = []
        for vuln in vulnerabilities:
            if isinstance(vuln, dict) and 'cve' in vuln:
                scan_cves.append(vuln['cve'])
        
        # Get NVD data
        nvd_data = results.get('nvd_results', {}).get('data', {})
        
        # Calculate CVSS statistics
        cvss_scores = []
        for cve_id, details in nvd_data.items():
            if isinstance(details, dict):
                score = details.get('cvss_metrics', {}).get('baseScore', 0)
                if score > 0:
                    cvss_scores.append(score)
        
        # Get KEV data
        kev_data = results.get('cisa_kev_results', {}).get('data', {})
        
        # Count KEV matches
        kev_matches = 0
        if kev_data:
            kev_cves = set(kev_data.keys())
            scan_cve_set = set(scan_cves)
            kev_matches = len(kev_cves.intersection(scan_cve_set))
        
        # Determine overall threat level
        threat_level = "LOW"
        if cvss_scores:
            max_score = max(cvss_scores)
            if max_score >= 9.0:
                threat_level = "CRITICAL"
            elif max_score >= 7.0:
                threat_level = "HIGH"
            elif max_score >= 4.0:
                threat_level = "MEDIUM"
        
        # Get VirusTotal data
        vt_data = results.get('virustotal_results', {}).get('data', {}).get('ip_analysis', {})
        malicious_count = vt_data.get('malicious', 0) if isinstance(vt_data, dict) else 0
        
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'unique_cves_analyzed': len(nvd_data),
            'cves_in_kev': kev_matches,
            'highest_cvss_score': max(cvss_scores) if cvss_scores else 0,
            'average_cvss_score': round(sum(cvss_scores)/len(cvss_scores), 1) if cvss_scores else 0,
            'threat_level': threat_level,
            'exposed_ports': len(scan_data.get('ports', [])),
            'malicious_indicators': malicious_count
        }
        
        return summary

    def generate_recommendations(self, results: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Check for critical CVEs from NVD
        nvd_data = results.get('nvd_results', {}).get('data', {})
        for cve_id, details in nvd_data.items():
            if isinstance(details, dict):
                score = details.get('cvss_metrics', {}).get('baseScore', 0)
                if score >= 9.0:
                    recommendations.append(f"IMMEDIATE ACTION: Patch {cve_id} (CVSS: {score})")
        
        # Check CISA KEV
        kev_data = results.get('cisa_kev_results', {}).get('data', {})
        scan_data = results.get('scan_data', {})
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                cve_id = vuln.get('cve')
                if cve_id in kev_data:
                    kev_info = kev_data[cve_id]
                    rec = f"PRIORITY: {cve_id} is in CISA KEV (Added: {kev_info.get('date_added', 'Unknown')})"
                    if kev_info.get('known_ransomware_use'):
                        rec += " - Known ransomware exploitation"
                    recommendations.append(rec)
        
        # Check Shodan exposure
        shodan_data = results.get('shodan_results', {}).get('data', {})
        if shodan_data and shodan_data.get('ports'):
            open_ports = len(shodan_data['ports'])
            if open_ports > 5:
                recommendations.append(f"SECURE CONFIGURATION: Reduce exposed ports ({open_ports} ports visible on Shodan)")
        
        # Add general recommendations if needed
        if len(recommendations) < 3:
            recommendations.extend([
                "IMPLEMENT: Regular vulnerability scanning schedule",
                "CONFIGURE: Automated patch management system",
                "REVIEW: Firewall rules and network segmentation",
                "ENABLE: Web Application Firewall for exposed services",
                "MONITOR: Threat intelligence feeds for emerging threats"
            ])
        
        return recommendations[:5]

    def generate_risk_assessment(self, results: Dict, summary: Dict) -> Dict:
        """Generate risk assessment based on all intelligence"""
        risk_score = 0
        risk_factors = []
        
        # Factor 1: CVSS scores (0-40 points)
        cvss_factor = min(summary.get('highest_cvss_score', 0) * 4, 40)
        risk_score += cvss_factor
        risk_factors.append(f"CVSS Severity: +{cvss_factor:.1f}")
        
        # Factor 2: KEV status (0-30 points)
        kev_factor = min(summary.get('cves_in_kev', 0) * 15, 30)
        risk_score += kev_factor
        risk_factors.append(f"CISA KEV Matches: +{kev_factor:.1f}")
        
        # Factor 3: VirusTotal reputation (0-15 points)
        vt_malicious = summary.get('malicious_indicators', 0)
        vt_factor = min(vt_malicious * 5, 15)
        risk_score += vt_factor
        risk_factors.append(f"Malicious Indicators: +{vt_factor:.1f}")
        
        # Factor 4: Exposure level (0-15 points)
        ports = summary.get('exposed_ports', 0)
        exposure_factor = min(ports * 3, 15)
        risk_score += exposure_factor
        risk_factors.append(f"Exposed Services: +{exposure_factor:.1f}")
        
        # Cap at 100
        risk_score = min(risk_score, 100)
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = "CRITICAL"
            color = "#dc3545"
        elif risk_score >= 60:
            risk_level = "HIGH"
            color = "#fd7e14"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
            color = "#ffc107"
        elif risk_score >= 20:
            risk_level = "LOW"
            color = "#28a745"
        else:
            risk_level = "INFO"
            color = "#6c757d"
        
        return {
            'overall_risk_score': round(risk_score, 1),
            'risk_level': risk_level,
            'risk_color': color,
            'risk_factors': risk_factors,
            'breakdown': {
                'cvss_impact': cvss_factor,
                'kev_impact': kev_factor,
                'reputation_impact': vt_factor,
                'exposure_impact': exposure_factor
            }
        }

    def generate_threat_report(self, layer1_data: Dict = None) -> Dict:
        """Main function to generate comprehensive threat report"""
        print("Processing Layer 1 data...")
        processed_data = self.process_layer1_data(layer1_data)
        
        print("Querying threat intelligence APIs...")
        
        # Extract indicators
        ip_address = processed_data.get('ip', processed_data.get('host', '8.8.8.8'))
        cve_list = []
        for vuln in processed_data.get('vulnerabilities', []):
            if isinstance(vuln, dict) and 'cve' in vuln:
                cve_list.append(vuln['cve'])
        
        # Query APIs
        results = {
            'scan_data': processed_data,
            'shodan_results': self.query_shodan(ip_address),
            'virustotal_results': self.query_virustotal({'ip': ip_address}),
            'nvd_results': self.query_nvd(cve_list),
            'cisa_kev_results': self.query_cisa_kev()
        }
        
        print("Generating visual analytics...")
        visuals = self.generate_visual_analytics(results)
        
        # Generate summary and recommendations
        summary = self.generate_summary(results, visuals)
        recommendations = self.generate_recommendations(results)
        risk_assessment = self.generate_risk_assessment(results, summary)
        
        # Compile final report
        threat_report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'data_sources': list(self.apis.keys()),
                'demo_mode': self.demo_mode,
                'layer1_input_summary': {
                    'host': processed_data.get('host'),
                    'vulnerability_count': len(processed_data.get('vulnerabilities', [])),
                    'port_count': len(processed_data.get('ports', []))
                }
            },
            'threat_intelligence': results,
            'visual_analytics': visuals,
            'summary': summary,
            'recommendations': recommendations,
            'risk_assessment': risk_assessment
        }
        
        return threat_report

    def save_report(self, report: Dict, filename: str = None) -> str:
        """Save report to JSON file in current directory"""
        # Use current directory
        current_dir = os.getcwd()
        
        # Create filename with timestamp
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_intelligence_report_{timestamp}.json"
        
        # Join current directory with filename
        filepath = os.path.join(current_dir, filename)
        
        # Save the report
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return filepath  # Return full path
    def print_report_summary(self, report: Dict):
        """Print a formatted summary of the report"""
        print("\n" + "="*60)
        print("THREAT INTELLIGENCE REPORT SUMMARY")
        print("="*60)
        
        summary = report.get('summary', {})
        risk = report.get('risk_assessment', {})
        
        print(f"\n📊 RISK ASSESSMENT:")
        print(f"   Overall Risk Score: {risk.get('overall_risk_score', 0)}/100")
        print(f"   Risk Level: {risk.get('risk_level', 'UNKNOWN')}")
        print(f"   Threat Level: {summary.get('threat_level', 'UNKNOWN')}")
        
        print(f"\n🔍 VULNERABILITY ANALYSIS:")
        print(f"   Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"   CVEs in CISA KEV: {summary.get('cves_in_kev', 0)}")
        print(f"   Highest CVSS Score: {summary.get('highest_cvss_score', 0)}")
        print(f"   Average CVSS Score: {summary.get('average_cvss_score', 0)}")
        
        print(f"\n🌐 NETWORK EXPOSURE:")
        print(f"   Exposed Ports: {summary.get('exposed_ports', 0)}")
        print(f"   Malicious Indicators: {summary.get('malicious_indicators', 0)}")
        
        print(f"\n🚨 TOP RECOMMENDATIONS:")
        for i, rec in enumerate(report.get('recommendations', [])[:3], 1):
            print(f"   {i}. {rec}")
        
        print(f"\n📈 VISUAL ANALYTICS GENERATED:")
        visuals = report.get('visual_analytics', {})
        visual_count = len(visuals)
        print(f"   • {visual_count} visual analytics components created")
        
        print(f"\n📁 Report generated: {report.get('metadata', {}).get('generated_at', 'Unknown')}")
        print(f"   Demo Mode: {report.get('metadata', {}).get('demo_mode', False)}")
        print("="*60)


def main():
    """Main execution function"""
    print("Starting Threat Intelligence Analysis...")
    print("="*60)
    
    # Initialize engine
    threat_engine = ThreatIntelligenceEngine()
    
    if threat_engine.demo_mode:
        print("⚠️  DEMO MODE - Using simulated responses")
        print("   To use real APIs, add your API keys to .env file")
        print("   Required: SHODAN_API_KEY, VIRUSTOTAL_API_KEY")
        print()
    
    # Generate threat report
    try:
        threat_report = threat_engine.generate_threat_report()
        
        # Save report (now it will save to current directory)
        filename = threat_engine.save_report(threat_report)
        
        # Print summary
        threat_engine.print_report_summary(threat_report)
        
        # Show where to find full report
        print(f"\n✅ Full report saved to: {os.path.abspath(filename)}")
        
        # Verify it's in current directory
        current_dir = os.getcwd()
        saved_dir = os.path.dirname(os.path.abspath(filename))
        if saved_dir == current_dir:
            print(f"📁 Location: Current working directory ({current_dir})")
        # Optionally display CVE details
        response = input("\nView detailed CVE information? (y/n): ").lower()
        if response == 'y':
            print("\nDetailed CVE Analysis:")
            print("-"*40)
            nvd_data = threat_report['threat_intelligence']['nvd_results']['data']
            for cve_id, details in nvd_data.items():
                if isinstance(details, dict):
                    print(f"\n🔹 {cve_id}")
                    desc = details.get('description', 'N/A')
                    if len(desc) > 100:
                        desc = desc[:100] + "..."
                    print(f"   Description: {desc}")
                    print(f"   CVSS Score: {details.get('cvss_metrics', {}).get('baseScore', 'N/A')}")
                    print(f"   Severity: {details.get('severity', 'N/A')}")
                    print(f"   Published: {details.get('published_date', 'N/A')}")
    
    except Exception as e:
        print(f"\n❌ Error generating report: {e}")
        print("Please check your internet connection and API keys.")


if __name__ == "__main__":
    main()