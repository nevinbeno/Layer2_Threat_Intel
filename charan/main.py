# main.py
import os
from threat_intelligence_engine import ThreatIntelligenceEngine

def main():
    """Main execution function"""
    print("Starting Threat Intelligence Analysis...")
    print("="*60)
    
    try:
        # Initialize engine
        threat_engine = ThreatIntelligenceEngine()
        
        # Generate threat report
        print("\n🔍 Collecting Threat Intelligence...")
        threat_report = threat_engine.generate_threat_report()
        
        # Save report
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
            nvd_data = threat_report['threat_intelligence']['nvd']['data']
            for cve_id, details in nvd_data.items():
                if isinstance(details, dict) and 'error' not in details:
                    print(f"\n🔹 {cve_id}")
                    desc = details.get('description', 'N/A')
                    if len(desc) > 100:
                        desc = desc[:100] + "..."
                    print(f"   Description: {desc}")
                    print(f"   CVSS Score: {details.get('cvss_metrics', {}).get('baseScore', 'N/A')}")
                    print(f"   Severity: {details.get('severity', 'N/A')}")
                    print(f"   Published: {details.get('published_date', 'N/A')}")
    
    except ValueError as e:
        print(f"\n❌ Configuration Error: {e}")
        print("\nPlease create a .env file with the following API keys:")
        print("SHODAN_API_KEY=your_shodan_key_here")
        print("VIRUSTOTAL_API_KEY=your_virustotal_key_here")
        print("VULNERS_API_KEY=your_vulners_key_here")
        print("\nYou can get API keys from:")
        print("- Shodan: https://account.shodan.io")
        print("- VirusTotal: https://www.virustotal.com/gui/join-us")
        print("- Vulners: https://vulners.com/features")
    
    except Exception as e:
        print(f"\n❌ Error generating report: {e}")
        print("Please check your internet connection and API keys.")

if __name__ == "__main__":
    main()