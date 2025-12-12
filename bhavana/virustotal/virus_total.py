#!/usr/bin/env python3
"""
virustotal.py

VirusTotal IP / URL scanning tool that reads API key from central config_loader.py
so all tools use the same .env / config_loader in the project root.

Usage:
  python virustotal.py
  python virustotal.py -f ips.txt   # for batch IP scans
  python virustotal.py ip 1.2.3.4
  python virustotal.py url "http://example.com"
"""

# --- shared config loader: ensure repo root is on sys.path ---
import sys
from pathlib import Path

# adjust parents[2] if your file depth differs (tool is typically at bhavana/<tool>/file.py)
project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root))

from config_loader import get_keys
# ----------------------------------------------------------

import requests
import json
import os
from typing import Dict, Any

# load keys
keys = get_keys()
VT_KEY = keys.get("virustotal")  # expects VT_API_KEY in .env

# Endpoints
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"

# Output folder under project root
OUTPUT_DIR = project_root / "outputs" / "virustotal_output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def get_next_filename(prefix: str = "vt_output") -> Path:
    count = len(list(OUTPUT_DIR.glob(f"{prefix}_*.json")))
    return OUTPUT_DIR / f"{prefix}_{count + 1}.json"


def scan_ip(api_key: str, ip: str) -> Dict[str, Any]:
    if not api_key:
        return {"error": "VirusTotal API key missing. Add VT_API_KEY to your .env."}

    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(VT_IP_URL.format(ip), headers=headers, timeout=15)
    except Exception as e:
        return {"error": f"Request failed: {e}"}

    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

    data = resp.json().get("data", {})
    attributes = data.get("attributes", {})

    # Clean simple output
    return {
        "ip": ip,
        "asn": attributes.get("asn"),
        "owner": attributes.get("as_owner"),
        "country": attributes.get("country"),
        "network": attributes.get("network"),
        "reputation_score": attributes.get("reputation"),
        "detection_counts": attributes.get("last_analysis_stats", {}),
        "community_votes": attributes.get("total_votes", {}),
        "tags": attributes.get("tags", [])
    }


def scan_multiple_ips(api_key: str, file_path: str) -> None:
    """Reads IPs from a file and scans each one."""
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        ips = [line.strip() for line in f if line.strip()]

    for ip in ips:
        print(f"\n🔍 Scanning IP: {ip}")
        result = scan_ip(api_key, ip)

        outfile = get_next_filename("vt_ip")
        outfile.write_text(json.dumps(result, indent=4), encoding="utf-8")

        print(f"✔ Saved result to: {outfile}")


def scan_url(api_key: str, url: str) -> Dict[str, Any]:
    if not api_key:
        return {"error": "VirusTotal API key missing. Add VT_API_KEY to your .env."}

    headers = {"x-apikey": api_key}
    data = {"url": url}

    try:
        resp = requests.post(VT_URL_SCAN, headers=headers, data=data, timeout=15)
    except Exception as e:
        return {"error": f"URL scan failed: {e}"}

    if resp.status_code not in (200, 201):
        return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

    return resp.json()


def interactive_menu() -> None:
    print("""
=== VIRUSTOTAL TOOL ===
1) Scan single IP
2) Scan multiple IPs from file
3) Scan URL
""")

    choice = input("Enter choice (1/2/3): ").strip()

    # 1️⃣ SINGLE IP SCAN
    if choice == "1":
        ip = input("Enter IP Address: ").strip()
        result = scan_ip(VT_KEY, ip)

        outfile = get_next_filename("vt_ip")
        outfile.write_text(json.dumps(result, indent=4), encoding="utf-8")

        print("\n===== CLEAN VIRUSTOTAL IP REPORT =====")
        print(json.dumps(result, indent=4))
        print("✔ Output saved to:", outfile)

    # 2️⃣ MULTIPLE IPS (FILE INPUT)
    elif choice == "2":
        file_path = input("Enter file name (example: ips.txt): ").strip()
        scan_multiple_ips(VT_KEY, file_path)

    # 3️⃣ URL SCAN
    elif choice == "3":
        url = input("Enter URL: ").strip()
        result = scan_url(VT_KEY, url)

        outfile = get_next_filename("vt_url")
        outfile.write_text(json.dumps(result, indent=4), encoding="utf-8")

        print("\n===== VIRUSTOTAL URL SCAN RESULT =====")
        print(json.dumps(result, indent=4))
        print("✔ Output saved to:", outfile)

    else:
        print("Invalid choice!")


def main():
    # quick CLI helpers:
    # python virustotal.py ip 1.2.3.4
    # python virustotal.py url http://example.com
    # python virustotal.py -f ips.txt
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "ip" and len(sys.argv) > 2:
            ip = sys.argv[2].strip()
            result = scan_ip(VT_KEY, ip)
            outfile = get_next_filename("vt_ip")
            outfile.write_text(json.dumps(result, indent=4), encoding="utf-8")
            print(json.dumps(result, indent=4))
            print("Saved:", outfile)
            return
        if cmd == "url" and len(sys.argv) > 2:
            url = sys.argv[2].strip()
            result = scan_url(VT_KEY, url)
            outfile = get_next_filename("vt_url")
            outfile.write_text(json.dumps(result, indent=4), encoding="utf-8")
            print(json.dumps(result, indent=4))
            print("Saved:", outfile)
            return
        if cmd in ("-f", "--file") and len(sys.argv) > 2:
            scan_multiple_ips(VT_KEY, sys.argv[2])
            return

    interactive_menu()


if __name__ == "__main__":
    main()
