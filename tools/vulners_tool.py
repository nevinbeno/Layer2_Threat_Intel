import requests
import os

class VulnersTool:
    def __init__(self):
        self.api_key = os.getenv("VULNERS_API_KEY")

    def query(self, cves):
        if not self.api_key:
            return {"skipped": True}

        results = {}
        for cve in cves:
            url = "https://vulners.com/api/v3/search/lucene/"
            params = {"query": f"cveId:{cve}", "apiKey": self.api_key}
            r = requests.get(url, params=params, timeout=10)
            results[cve] = r.json() if r.status_code == 200 else {}

        return results
