import requests
import json

def fetch_cve(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/2.0/{cve_id}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
                vuln = data["vulnerabilities"][0]["cve"]
                print(f"CVE ID: {vuln['id']}")
                print(f"Description: {vuln['descriptions'][0]['value']}")
                print(f"Published: {vuln['published']}")
            else:
                print("❌ CVE not found in NVD database!")
        else:
            print(f"❌ HTTP Error {response.status_code}")
    except Exception as e:
        print("❌ Exception:", e)

# Test with a real CVE
fetch_cve("CVE-2021-44228")
