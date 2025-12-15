import requests
import time

class NVDTool:
    def __init__(self):
        self.base = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def query(self, cves):
        results = {}
        for cve in cves:
            url = f"{self.base}?cveId={cve}"
            r = requests.get(url, timeout=10)

            if r.status_code == 200:
                data = r.json()
                results[cve] = data.get("vulnerabilities", [{}])[0].get("cve", {})
            else:
                results[cve] = {"error": "NVD lookup failed"}

            time.sleep(0.6)

        return results
