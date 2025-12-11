# threat_intelligence_engine.py
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict

from shodan_client import ShodanClient
from virustotal_client import VirusTotalClient
from cisa_kev_client import CISAKEVClient
from vulners_client import VulnersClient
from nvd_client import NVDClient

class ThreatIntelligenceEngine:
    def __init__(self):
        """Initialize all threat intelligence clients"""
        self.clients = {
            'shodan': ShodanClient(),
            'virustotal': VirusTotalClient(),
            'cisa_kev': CISAKEVClient(),
            'vulners': VulnersClient(),
            'nvd': NVDClient()
        }
        
        # Demo mode flag
        self.demo_mode = (
            self.clients['shodan'].demo_mode or
            self.clients['virustotal'].demo_mode or
            self.clients['vulners'].demo_mode
        )
    
    def process_layer1_data(self, scan_data: Dict = None) -> Dict[str, Any]:
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
    
    def collect_intelligence(self, processed_data: Dict) -> Dict[str, Any]:
        """Collect intelligence from all sources"""
        # Extract indicators
        ip_address = processed_data.get('ip', processed_data.get('host', '8.8.8.8'))
        cve_list = [
            vuln['cve'] for vuln in processed_data.get('vulnerabilities', [])
            if isinstance(vuln, dict) and 'cve' in vuln
        ]
        
        print(f"Collecting intelligence for IP: {ip_address}")
        print(f"Analyzing {len(cve_list)} CVEs...")
        
        # Query all intelligence sources
        results = {
            'scan_data': processed_data,
            'shodan': self.clients['shodan'].query_ip(ip_address),
            'virustotal': self.clients['virustotal'].query_ip(ip_address),
            'nvd': self.clients['nvd'].query_cves(cve_list),
            'cisa_kev': self.clients['cisa_kev'].query_kev(),
            'vulners': self.clients['vulners'].query_vulnerabilities(cve_list)
        }
        
        return results
    
    def generate_visual_analytics(self, results: Dict) -> Dict[str, Any]:
        """Generate visual analytics from threat intelligence data"""
        visuals = {}
        
        # Extract data
        nvd_data = results.get('nvd', {}).get('data', {})
        kev_data = results.get('cisa_kev', {}).get('data', {})
        scan_data = results.get('scan_data', {})
        shodan_data = results.get('shodan', {}).get('data', {})
        
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
        scan_cves = [
            v.get('cve') for v in scan_data.get('vulnerabilities', [])
            if isinstance(v, dict) and 'cve' in v
        ]
        
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
        
        # 4. Shodan Exposure Summary
        if shodan_data:
            visuals['shodan_summary'] = {
                'type': 'exposure_summary',
                'open_ports': shodan_data.get('ports', []),
                'vulnerabilities_found': shodan_data.get('vulnerabilities', []),
                'hostnames': shodan_data.get('hostnames', []),
                'location': shodan_data.get('location', {})
            }
        
        return visuals
    
    def generate_summary(self, results: Dict) -> Dict[str, Any]:
        """Generate executive summary"""
        scan_data = results.get('scan_data', {})
        vulnerabilities = scan_data.get('vulnerabilities', [])
        nvd_data = results.get('nvd', {}).get('data', {})
        kev_data = results.get('cisa_kev', {}).get('data', {})
        vt_data = results.get('virustotal', {}).get('data', {}).get('ip_analysis', {})
        shodan_data = results.get('shodan', {}).get('data', {})
        
        # Calculate CVSS statistics
        cvss_scores = []
        for cve_id, details in nvd_data.items():
            if isinstance(details, dict):
                score = details.get('cvss_metrics', {}).get('baseScore', 0)
                if score > 0:
                    cvss_scores.append(score)
        
        # Count KEV matches
        scan_cves = [v.get('cve') for v in vulnerabilities if isinstance(v, dict) and 'cve' in v]
        kev_matches = 0
        if kev_data:
            kev_cves = set(kev_data.keys())
            kev_matches = len(set(scan_cves).intersection(kev_cves))
        
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
        
        # VirusTotal data
        malicious_count = vt_data.get('malicious', 0) if isinstance(vt_data, dict) else 0
        
        # Shodan data
        exposed_ports = len(shodan_data.get('ports', [])) if shodan_data else 0
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'unique_cves_analyzed': len(nvd_data),
            'cves_in_kev': kev_matches,
            'highest_cvss_score': max(cvss_scores) if cvss_scores else 0,
            'average_cvss_score': round(sum(cvss_scores)/len(cvss_scores), 1) if cvss_scores else 0,
            'threat_level': threat_level,
            'exposed_ports': exposed_ports,
            'malicious_indicators': malicious_count
        }
    
    def generate_recommendations(self, results: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        nvd_data = results.get('nvd', {}).get('data', {})
        kev_data = results.get('cisa_kev', {}).get('data', {})
        scan_data = results.get('scan_data', {})
        shodan_data = results.get('shodan', {}).get('data', {})
        
        # Check critical CVEs
        for cve_id, details in nvd_data.items():
            if isinstance(details, dict):
                score = details.get('cvss_metrics', {}).get('baseScore', 0)
                if score >= 9.0:
                    recommendations.append(f"IMMEDIATE ACTION: Patch {cve_id} (CVSS: {score})")
        
        # Check CISA KEV
        for vuln in scan_data.get('vulnerabilities', []):
            if isinstance(vuln, dict):
                cve_id = vuln.get('cve')
                if cve_id in kev_data:
                    kev_info = kev_data[cve_id]
                    rec = f"PRIORITY: {cve_id} is in CISA KEV (Added: {kev_info.get('date_added', 'Unknown')})"
                    if kev_info.get('known_ransomware_use'):
                        rec += " - Known ransomware exploitation"
                    recommendations.append(rec)
        
        # Check Shodan exposure
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
    
    def generate_risk_assessment(self, results: Dict, summary: Dict) -> Dict[str, Any]:
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
    
    def generate_threat_report(self, layer1_data: Dict = None) -> Dict[str, Any]:
        """Main function to generate comprehensive threat report"""
        print("Processing Layer 1 data...")
        processed_data = self.process_layer1_data(layer1_data)
        
        print("Collecting threat intelligence from all sources...")
        results = self.collect_intelligence(processed_data)
        
        print("Generating visual analytics...")
        visuals = self.generate_visual_analytics(results)
        
        # Generate summary and recommendations
        summary = self.generate_summary(results)
        recommendations = self.generate_recommendations(results)
        risk_assessment = self.generate_risk_assessment(results, summary)
        
        # Compile final report
        threat_report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'data_sources': list(self.clients.keys()),
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
        current_dir = os.getcwd()
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_intelligence_report_{timestamp}.json"
        
        filepath = os.path.join(current_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return filepath
    
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