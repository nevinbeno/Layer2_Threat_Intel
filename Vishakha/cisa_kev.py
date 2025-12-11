import requests
import json

def fetch_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    print("Fetching CISA KEV Data...")
    
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        
        print("\nTotal CVEs in KEV List:", len(data["vulnerabilities"]))
        print("\nExample CVE Entry:\n")
        print(json.dumps(data["vulnerabilities"][0], indent=2))
        
    else:
        print("Error:", response.status_code)

if __name__ == "__main__":
    fetch_cisa_kev()
