from datetime import datetime


def build_risk_input(level2_output: dict) -> dict:
    """
    Build Layer-3 summarized input for Risk Scoring Engine
    """

    vulns = level2_output.get("vulnerabilities", [])
    intel = level2_output.get("intelligence", {})

    nvd_data = intel.get("nvd", {})
    kev_data = intel.get("cisa_kev", {})

    layer3 = {
        "layer": "layer_3_risk_engine",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "vulnerabilities": []
    }

    for v in vulns:
        cve = v.get("cve")
        nvd = nvd_data.get(cve, {})
        kev = kev_data.get(cve)

        # CVSS v3 extraction
        cvss_metrics = nvd.get("metrics", {}).get("cvssMetricV31", [])
        cvss_data = cvss_metrics[0]["cvssData"] if cvss_metrics else {}

        # Description
        descriptions = nvd.get("descriptions", [])
        description = descriptions[0]["value"] if descriptions else "N/A"

        # Vulnerability type (CWE)
        weaknesses = nvd.get("weaknesses", [])
        vuln_type = (
            weaknesses[0]["description"][0]["value"]
            if weaknesses else "UNKNOWN"
        )

        # Exploit check
        references = nvd.get("references", [])
        exploit_available = any(
            "Exploit" in ref.get("tags", []) for ref in references
        )

        # Summary (important for Layer-3)
        summary_parts = [
            f"{v.get('severity')} severity",
            f"CVSS {cvss_data.get('baseScore', v.get('cvss'))}",
            f"Attack Vector: {cvss_data.get('attackVector', 'UNKNOWN')}"
        ]

        if kev:
            summary_parts.append("Known Exploited (CISA KEV)")

        if exploit_available:
            summary_parts.append("Public exploit available")

        summary = ", ".join(summary_parts)

        layer3["vulnerabilities"].append({
            "cve_id": cve,
            "severity": v.get("severity"),
            "cvss_score": cvss_data.get("baseScore", v.get("cvss")),

            "attack_vector": cvss_data.get("attackVector", "UNKNOWN"),
            "attack_complexity": cvss_data.get("attackComplexity", "UNKNOWN"),
            "privileges_required": cvss_data.get("privilegesRequired", "UNKNOWN"),
            "user_interaction": cvss_data.get("userInteraction", "UNKNOWN"),

            "vulnerability_type": vuln_type,
            "affected_service": v.get("service"),

            "is_kev": kev is not None,
            "exploit_available": exploit_available,

            "impact": {
                "confidentiality": cvss_data.get("confidentialityImpact"),
                "integrity": cvss_data.get("integrityImpact"),
                "availability": cvss_data.get("availabilityImpact")
            },

            "summary": summary
        })

    return layer3
