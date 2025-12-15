import requests
import os

class ShodanTool:
    def __init__(self):
        self.api_key = os.getenv("SHODAN_API_KEY")

    def query(self, ip):
        if not self.api_key or not ip:
            return {"skipped": True}

        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_key}"
        r = requests.get(url, timeout=10)

        if r.status_code != 200:
            return {"error": r.text}

        data = r.json()
        return {
            "ports": data.get("ports", []),
            "org": data.get("org"),
            "vulns": list(data.get("vulns", {}).keys())
        }
