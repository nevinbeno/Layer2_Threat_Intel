#!/usr/bin/env python3
"""
cisa_kev.py

CISA Known Exploited Vulnerabilities (KEV) lookup tool.
Reads shared config from project root via config_loader.get_keys() so all tools
use a single .env / config_loader in the repo root.

Usage:
  python cisa_kev.py CVE-2024-3400
  python cisa_kev.py         # interactive prompt
  python cisa_kev.py -f file_with_cves.txt  # batch: one CVE per line
"""

# --- shared config loader: ensure repo root is on sys.path ---
import sys
from pathlib import Path

# adjust parents[2] if this file is at a different depth from project root
project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root))

from config_loader import get_keys
# ----------------------------------------------------------

import requests
import json
import time
import hashlib
from datetime import datetime

# Load keys if needed (CISA KEV is public, but keep pattern)
keys = get_keys()

# ------------------------------------------------------------
# Settings (use project-root paths so outputs live in repo root)
# ------------------------------------------------------------
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUTPUT_DIR = project_root / "cisa_outputs"
CACHE_FILE = project_root / "cisa_kev_cache.json"
CACHE_HOURS = 6

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------
# Small utilities
# ------------------------------------------------------------
def now_time():
    return datetime.utcnow().isoformat() + "Z"


def cve_to_filename(cve: str) -> str:
    return cve.replace("-", "_")


# ------------------------------------------------------------
# KEV Fetching with optional caching
# ------------------------------------------------------------
def load_kev_feed() -> dict:
    """Fetches KEV feed, or loads cache if recent."""
    try:
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

    except requests.RequestException as e:
        # If network fails but cache exists, load stale cache as fallback
        if CACHE_FILE.exists():
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                print(f"Warning: network error ({e}), using cached KEV feed.")
                return json.load(f)
        raise


# ------------------------------------------------------------
# KEV lookup
# ------------------------------------------------------------
def find_cve_in_kev(cve: str, kev_data: dict) -> dict | None:
    for entry in kev_data.get("vulnerabilities", []):
        if entry.get("cveID") == cve:
            return entry
    return None


# ------------------------------------------------------------
# Save result to JSON
# ------------------------------------------------------------
def save_result(cve: str, data: dict) -> Path:
    # Generate a SHA prefix to differentiate files
    sha_prefix = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:8]
    filename = f"kev_{cve_to_filename(cve)}_{sha_prefix}.json"
    filepath = OUTPUT_DIR / filename

    payload = {
        "metadata": {
            "generated_at": now_time(),
            "source": "CISA KEV Feed",
            "cve_checked": cve
        },
        "result": data
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4)

    return filepath


# ------------------------------------------------------------
# Processing helpers
# ------------------------------------------------------------
def check_and_save_cve(cve: str, kev_data: dict) -> None:
    cve = cve.strip().upper()
    if not cve:
        return

    entry = find_cve_in_kev(cve, kev_data)
    if entry:
        print(f"\n✔ {cve} is present in CISA KEV (known exploited).")
        print(f"  Vendor:  {entry.get('vendorProject')}")
        print(f"  Product: {entry.get('product')}")
        print(f"  Date Added: {entry.get('dateAdded')}")
        print(f"  Description: {entry.get('shortDescription')}")
        print(f"  Known Ransomware Use: {entry.get('knownRansomwareCampaignUse', False)}")

        out_path = save_result(cve, entry)
        print(f"  JSON saved: {out_path}")
    else:
        print(f"\n✖ {cve} NOT found in the CISA KEV list.")


# ------------------------------------------------------------
# CLI / main
# ------------------------------------------------------------
def main():
    try:
        kev_data = load_kev_feed()
    except Exception as e:
        print(f"Fatal: Unable to load KEV feed: {e}")
        return

    # Command-line handling
    if len(sys.argv) > 1:
        # support batch file: python cisa_kev.py -f file.txt
        if sys.argv[1] in ("-f", "--file") and len(sys.argv) > 2:
            file_path = Path(sys.argv[2])
            if not file_path.exists():
                print(f"File not found: {file_path}")
                return
            lines = [ln.strip() for ln in file_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            for cve in lines:
                check_and_save_cve(cve, kev_data)
            return
        else:
            cve = sys.argv[1].strip()
            check_and_save_cve(cve, kev_data)
            return

    # Interactive
    print("=== CISA KEV Lookup Tool ===")
    cve = input("Enter CVE to check (example: CVE-2024-3400): ").strip()
    if not cve:
        print("No CVE entered. Exiting.")
        return
    check_and_save_cve(cve, kev_data)


if __name__ == "__main__":
    main()
