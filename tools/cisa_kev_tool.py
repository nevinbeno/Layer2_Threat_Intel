import requests

class CISAKEVTool:
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def query(self, cves):
        r = requests.get(self.URL, timeout=10)
        if r.status_code != 200:
            return {}

        kev = r.json()["vulnerabilities"]
        kev_map = {v["cveID"]: v for v in kev}

        return {cve: kev_map[cve] for cve in cves if cve in kev_map}
