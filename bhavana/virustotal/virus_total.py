import requests
import json
from pathlib import Path
import os

VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"

# Output folder
OUTPUT_DIR = Path("outputs/virustotal_output")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def get_next_filename(prefix="vt_output"):
    count = len(list(OUTPUT_DIR.glob(f"{prefix}_*.json")))
    return OUTPUT_DIR / f"{prefix}_{count + 1}.json"


def scan_ip(api_key, ip):
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


def scan_multiple_ips(api_key, file_path):
    """Reads IPs from a file and scans each one."""
    with open(file_path, "r") as f:
        ips = [line.strip() for line in f if line.strip()]

    for ip in ips:
        print(f"\n🔍 Scanning IP: {ip}")
        result = scan_ip(api_key, ip)

        outfile = get_next_filename("vt_ip")
        outfile.write_text(json.dumps(result, indent=4), encoding="utf-8")

        print(f"✔ Saved result to: {outfile}")


def scan_url(api_key, url):
    headers = {"x-apikey": api_key}
    data = {"url": url}

    try:
        resp = requests.post(VT_URL_SCAN, headers=headers, data=data, timeout=15)
    except Exception as e:
        return {"error": f"URL scan failed: {e}"}

    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

    return resp.json()


if __name__ == "__main__":
    # Your VirusTotal API key
    api_key = "69efa3be46eb7439eebd15636c0f94368566a3fd3371954e85dc536deb762ccb"

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
        result = scan_ip(api_key, ip)

        outfile = get_next_filename("vt_ip")
        outfile.write_text(json.dumps(result, indent=4), encoding="utf-8")

        print("\n===== CLEAN VIRUSTOTAL IP REPORT =====")
        print(json.dumps(result, indent=4))
        print("✔ Output saved to:", outfile)

    # 2️⃣ MULTIPLE IPS (FILE INPUT)
    elif choice == "2":
        file_path = input("Enter file name (example: ips.txt): ").strip()

        if not os.path.exists(file_path):
            print("❌ File not found.")
        else:
            scan_multiple_ips(api_key, file_path)

    # 3️⃣ URL SCAN
    elif choice == "3":
        url = input("Enter URL: ").strip()
        result = scan_url(api_key, url)

        outfile = get_next_filename("vt_url")
        outfile.write_text(json.dumps(result, indent=4), encoding="utf-8")

        print("\n===== VIRUSTOTAL URL SCAN RESULT =====")
        print(json.dumps(result, indent=4))
        print("✔ Output saved to:", outfile)

    else:
        print("Invalid choice!")
