import requests
import json

# Example CVE ID
cve_id = "CVE-2025-9999"

# NVD API URL
url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"

response = requests.get(url)

print("Status Code:", response.status_code)

if response.status_code == 200:
    data = response.json()
    cve_data = data["result"]["CVE_Items"][0]["cve"]

    print("\n--- CVE Summary ---")
    print("CVE ID:", cve_data["CVE_data_meta"]["ID"])
    print("Description:", cve_data["description"]["description_data"][0]["value"])
    print("Published Date:", data["result"]["CVE_Items"][0]["publishedDate"])
    print("Last Modified:", data["result"]["CVE_Items"][0]["lastModifiedDate"])

    # Optional: CVSS v3 Score
    impact = data["result"]["CVE_Items"][0].get("impact", {})
    base_metric_v3 = impact.get("baseMetricV3", {})
    cvss_v3 = base_metric_v3.get("cvssV3", {})
    if cvss_v3:
        print("CVSS v3 Base Score:", cvss_v3.get("baseScore"))
        print("CVSS v3 Severity:", cvss_v3.get("baseSeverity"))

else:
    print("Error fetching CVE data")
