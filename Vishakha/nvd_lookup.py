import requests
import json
from dotenv import load_dotenv
import os

load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

def get_cve_details(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/2.0/{cve_id}"
    headers = {
        "apiKey": NVD_API_KEY,
        "User-Agent": "ThreatIntel/1.0"
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print("Error:", response.status_code)
        return None

cve = input("Enter CVE ID: ")
output = get_cve_details(cve)

if output:
    print(json.dumps(output, indent=2))
