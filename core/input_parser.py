import json

class InputParser:
    def parse(self, file_path: str) -> dict:
        with open(file_path, "r") as f:
            data = json.load(f)

        return {
            "asset": data.get("asset", {}),
            "vulnerabilities": [
                {
                    "cve": v.get("cve"),
                    "severity": v.get("severity"),
                    "cvss": v.get("cvss_score"),
                    "service": v.get("service")
                }
                for v in data.get("vulnerabilities", [])
            ]
        }
