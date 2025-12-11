import requests
import json
import os
import time
import hashlib
from pathlib import Path
from datetime import datetime, timedelta

# ------------------------------------------------------------
# Settings
# ------------------------------------------------------------
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUTPUT_DIR = Path("cisa_kev_outputs")
CACHE_FILE = Path("cisa_kev_cache.json")
CACHE_HOURS = 6
OUTPUT_DIR.mkdir(exist_ok=True)


# ------------------------------------------------------------
# Small utilities
# ------------------------------------------------------------
def now_time():
    return datetime.utcnow().isoformat() + "Z"


def cve_to_filename(cve):
    return cve.replace("-", "_")


# ------------------------------------------------------------
# KEV Fetching with optional caching
# ------------------------------------------------------------
def load_kev_feed():
    """Fetches KEV feed, or loads cache if recent."""

    # Use cache if it exists and is recent
    if CACHE_FILE.exists():
        age_hours = (datetime.utcnow() - datetime.utcfromtimestamp(CACHE_FILE.stat().st_mtime)).total_seconds() / 3600
        if age_hours < CACHE_HOURS:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)

    # Fetch fresh feed
    resp = requests.get(KEV_URL, timeout=20)
    resp.raise_for_status()
    kev_data = resp.json()

    # Save cache
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(kev_data, f, indent=2)

    return kev_data


# ------------------------------------------------------------
# KEV lookup
# ------------------------------------------------------------
def find_cve_in_kev(cve, kev_data):
    for entry in kev_data.get("vulnerabilities", []):
        if entry.get("cveID") == cve:
            return entry
    return None


# ------------------------------------------------------------
# Save result to JSON
# ------------------------------------------------------------
def save_result(cve, data):
    # Generate a SHA prefix to differentiate files
    sha_prefix = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:8]

    filename = f"kev_{cve_to_filename(cve)}_{sha_prefix}.json"
    filepath = OUTPUT_DIR / filename

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump({
            "metadata": {
                "generated_at": now_time(),
                "source": "CISA KEV Feed",
                "cve_checked": cve
            },
            "result": data
        }, f, indent=4)

    return filepath


# ------------------------------------------------------------
# Main program
# ------------------------------------------------------------
def main():
    print("=== CISA KEV Lookup Tool ===")

    cve = input("Enter CVE to check (example: CVE-2024-3400): ").strip()

    # Load KEV feed
    kev_data = load_kev_feed()

    # Check CVE
    result = find_cve_in_kev(cve, kev_data)

    if result:
        print("\n✔ CVE is present in CISA KEV (known exploited).")

        # Show short summary
        print(f"Vendor:  {result.get('vendorProject')}")
        print(f"Product: {result.get('product')}")
        print(f"Date Added: {result.get('dateAdded')}")
        print(f"Description: {result.get('shortDescription')}")
        print(f"Ransomware: {result.get('knownRansomwareCampaignUse', False)}")

        # Save JSON output
        out_path = save_result(cve, result)
        print(f"\nJSON saved: {out_path}")

    else:
        print("\n✖ CVE NOT found in the CISA KEV list.")


if __name__ == "__main__":
    main()
