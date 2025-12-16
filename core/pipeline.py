import json
from datetime import datetime

from core.input_parser import InputParser
from core.validator import Validator

from tools.shodan_tool import ShodanTool
from tools.virustotal_tool import VirusTotalTool
from tools.nvd_tool import NVDTool
from tools.vulners_tool import VulnersTool
from tools.cisa_kev_tool import CISAKEVTool


class ThreatIntelPipeline:
    def __init__(self):
        self.parser = InputParser()
        self.validator = Validator()

        self.shodan = self._init_tool(ShodanTool)
        self.virustotal = self._init_tool(VirusTotalTool)

        self.nvd = NVDTool()
        self.vulners = VulnersTool()
        self.cisa = CISAKEVTool()

    # ==================================================
    def _init_tool(self, tool_class):
        try:
            return tool_class()
        except Exception as e:
            return {"fallback": True, "reason": str(e)}

    # ==================================================
    def run(self, input_file: str) -> dict:
        parsed = self.parser.parse(input_file)
        validation = self.validator.validate(parsed)

        if not validation["is_valid"]:
            return {"status": "failed", "errors": validation["errors"]}

        asset = parsed["asset"]
        vulns = parsed["vulnerabilities"]
        cves = [v["cve"] for v in vulns if v.get("cve")]

        # ---------------- INTELLIGENCE ----------------
        intel = {
            "shodan": self._execute_tool(self.shodan, asset.get("ip")),
            "virustotal": self._execute_tool(self.virustotal, asset.get("ip")),
            "nvd": self.nvd.query(cves),
            "vulners": self.vulners.query(cves),
            "cisa_kev": self.cisa.query(cves)
        }

        # ---------------- LEVEL-2 OUTPUT ----------------
        with open("output/level2.json", "w") as f:
            json.dump({
                "asset": asset,
                "vulnerabilities": vulns,
                "intelligence": intel,
                "generated_at": datetime.utcnow().isoformat()
            }, f, indent=2)

        # ---------------- DASHBOARD SUMMARY ----------------
        dashboard = self._generate_dashboard_summary(asset, vulns, intel)
        with open("output/dashboard_summary.json", "w") as f:
            json.dump(dashboard, f, indent=2)

        # ---------------- VULNERABILITY DETAILS (NEW) ----------------
        vuln_details = self._generate_vulnerability_details(asset, vulns, intel)
        with open("output/vulnerability_details.json", "w") as f:
            json.dump(vuln_details, f, indent=2)

        return {"status": "success"}

    # ==================================================
    def _execute_tool(self, tool, target):
        if isinstance(tool, dict) and tool.get("fallback"):
            return {"executed": True, "mode": "limited", "data": {}}
        if not target:
            return {"executed": True, "mode": "limited", "data": {}}
        try:
            return {"executed": True, "mode": "full", "data": tool.query(target)}
        except Exception as e:
            return {"executed": True, "mode": "error", "error": str(e), "data": {}}

    # ==================================================
    # DASHBOARD SUMMARY (UNCHANGED LOGIC)
    # ==================================================
    def _generate_dashboard_summary(self, asset, vulns, intel):
        cvss_scores = [v["cvss"] for v in vulns if isinstance(v.get("cvss"), (int, float))]
        avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else 0
        max_cvss = max(cvss_scores) if cvss_scores else 0

        severity_dist = {}
        for v in vulns:
            sev = v.get("severity", "UNKNOWN")
            severity_dist[sev] = severity_dist.get(sev, 0) + 1

        kev_count = len(intel.get("cisa_kev", {}))

        return {
            "dashboard_version": "1.0",
            "generated_at": datetime.utcnow().isoformat(),
            "asset_summary": asset,
            "vulnerability_metrics": {
                "total_vulnerabilities": len(vulns),
                "average_cvss": avg_cvss,
                "highest_cvss": max_cvss,
                "severity_distribution": severity_dist,
                "kev_exploited_count": kev_count
            },
            "risk": {
                "risk_level": self._calculate_risk(avg_cvss, max_cvss, kev_count)
            }
        }

    # ==================================================
    # NEW: VULNERABILITY DETAILS OUTPUT
    # ==================================================
    def _generate_vulnerability_details(self, asset, vulns, intel):
        nvd_data = intel.get("nvd", {}).get("data", {})
        details = []

        for v in vulns:
            cve = v.get("cve")
            nvd = nvd_data.get(cve, {})

            cvss = nvd.get("cvss_metrics", {})
            details.append({
                "cve_id": cve,
                "severity": nvd.get("severity", v.get("severity")),
                "cvss_score": cvss.get("baseScore", v.get("cvss")),
                "attack_vector": cvss.get("attackVector", "UNKNOWN"),
                "vulnerability_type": nvd.get("cwe_list", []),
                "summary": nvd.get("description", "")[:150],
                "description": nvd.get("description", ""),
                "affected_assets": [
                    {
                        "ip": asset.get("ip"),
                        "hostname": asset.get("hostname"),
                        "exposure": asset.get("exposure")
                    }
                ]
            })

        return {
            "generated_at": datetime.utcnow().isoformat(),
            "total_vulnerabilities": len(details),
            "vulnerabilities": details
        }

    # ==================================================
    def _calculate_risk(self, avg, max_score, kev):
        if kev > 0 or max_score >= 9:
            return "CRITICAL"
        if max_score >= 7:
            return "HIGH"
        if avg >= 4:
            return "MEDIUM"
        return "LOW"
