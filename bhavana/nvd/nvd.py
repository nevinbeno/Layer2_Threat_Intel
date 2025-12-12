#!/usr/bin/env python3
"""
nvd.py

NVD CVE lookup tool that reads the NVD API key from a central config_loader
(so all tools use the same .env / config_loader in the project root).

Usage:
  python nvd.py            # interactive menu: single CVE or CSV batch
  python nvd.py CVE-2021-44228   # lookup single CVE via arg
  python nvd.py -f cves.csv      # process CSV (column name: cve_id)
"""

# --- shared config loader: ensure repo root is on sys.path ---
import sys
from pathlib import Path

# adjust parents[2] if your file location depth is different
project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root))

from config_loader import get_keys
# ----------------------------------------------------------

import requests
import json
import csv
import os
from typing import Tuple, Optional

# load keys
keys = get_keys()
NVD_KEY = keys.get("nvd")   # expects NVD_API_KEY in .env

# ---------- CONFIG & PATHS ----------
ALLOWED_DOMAINS = [
    "microsoft.com", "oracle.com", "redhat.com", "apple.com",
    "cisco.com", "vmware.com", "paloaltonetworks.com"
]

OUTPUT_DIR = project_root / "nvd_output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ---------- UTILITIES ----------
def extract_short_info(data: dict) -> dict:
    """Extract only important NVD fields for a clean short output."""
    try:
        item = data["vulnerabilities"][0]["cve"]

        desc = ""
        if item.get("descriptions"):
            # find english description
            for d in item["descriptions"]:
                if d.get("lang", "").lower() in ("en", "eng", ""):
                    desc = d.get("value", "")
                    break
            if not desc and item["descriptions"]:
                desc = item["descriptions"][0].get("value", "")

        published = item.get("published", "Unknown")

        # CWE
        cwe = "Unknown"
        if item.get("weaknesses"):
            cwe_description = item["weaknesses"][0].get("description", [])
            if cwe_description:
                cwe = cwe_description[0].get("value", "Unknown")

        # Filter references
        refs = [
            r["url"]
            for r in item.get("references", [])
            if any(domain in r.get("url", "") for domain in ALLOWED_DOMAINS)
        ]

        # Always include the official NVD page
        if "id" in item:
            refs.insert(0, f"https://nvd.nist.gov/vuln/detail/{item['id']}")

        # Severity + Score
        severity = "Unknown"
        score = None
        metrics = item.get("metrics", {})

        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss.get("baseSeverity", severity)
            score = cvss.get("baseScore", score)
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]
            severity = cvss.get("baseSeverity", severity)
            score = cvss.get("baseScore", score)
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]
            severity = cvss.get("baseSeverity", severity)
            score = cvss.get("baseScore", score)

        return {
            "cve_id": item.get("id"),
            "severity": severity,
            "score": score,
            "published": published,
            "description": desc,
            "cwe": cwe,
            "references": refs
        }

    except Exception as e:
        return {"error": f"Parsing error: {e}"}


def lookup_cve(cve_id: str) -> Tuple[Optional[dict], Optional[str]]:
    """Fetch NVD record for a CVE. Returns (data, error_message)."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    try:
        response = requests.get(url, headers=headers, timeout=20)
    except requests.RequestException as e:
        return None, f"Request failed: {e}"

    if response.status_code != 200:
        return None, f"HTTP {response.status_code}: {response.text[:200]}"

    try:
        data = response.json()
    except ValueError:
        return None, "Invalid JSON response"

    if not data.get("vulnerabilities"):
        return None, "No data found"

    return data, None


def save_short_json(cve_id: str, clean_data: dict) -> Path:
    file_name = f"nvd_{cve_id.replace('-', '_')}.json"
    path = OUTPUT_DIR / file_name
    with open(path, "w", encoding="utf-8") as f:
        json.dump(clean_data, f, indent=4)
    return path


# ---------- CSV BATCH ----------
def process_csv(csv_file: str) -> None:
    results = []
    print("\n📄 Reading CSV...")

    if not os.path.exists(csv_file):
        print(f"File not found: {csv_file}")
        return

    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve = row.get("cve_id", "").strip()
            if not cve:
                continue
            print(f"\n🔍 Checking: {cve}")
            data, error = lookup_cve(cve)
            if error:
                print(f"❌ Error for {cve}: {error}")
                continue
            clean_info = extract_short_info(data)
            save_short_json(cve, clean_info)
            results.append(clean_info)

    # Save combined CSV summary
    summary_path = OUTPUT_DIR / "nvd_combined_summary.csv"
    keys = ["cve_id", "severity", "score", "published", "cwe"]

    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for item in results:
            writer.writerow({k: item.get(k, "") for k in keys})

    print(f"\n📁 Combined summary saved as: {summary_path}")


# ---------- MAIN ----------
def main():
    # Allow passing single CVE or -f file or interactive
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg in ("-f", "--file") and len(sys.argv) > 2:
            process_csv(sys.argv[2])
            return
        else:
            cve = arg.strip()
            data, error = lookup_cve(cve)
            if error:
                print(f"\n❌ Error: {error}")
                return
            clean_info = extract_short_info(data)
            out = save_short_json(cve, clean_info)
            print(f"\n📁 Clean JSON saved: {out}")
            return

    # Interactive menu
    print("=== NVD Tool: Single or Multiple CVE Lookup ===")
    print("1) Check one CVE")
    print("2) Upload CSV file of CVEs\n")

    choice = input("Enter choice (1 or 2): ").strip()

    if choice == "1":
        cve_id = input("Enter CVE ID: ").strip()
        if not cve_id:
            print("No CVE entered.")
            return
        data, error = lookup_cve(cve_id)
        if error:
            print(f"\n❌ Error: {error}")
            return
        clean_info = extract_short_info(data)
        out = save_short_json(cve_id, clean_info)
        print(f"\n📁 Clean JSON saved: {out}")

    elif choice == "2":
        csv_file = input("Enter CSV file name (example: cves.csv): ").strip()
        if not csv_file:
            print("No file provided.")
            return
        process_csv(csv_file)

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
