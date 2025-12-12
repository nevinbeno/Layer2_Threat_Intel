#!/usr/bin/env python3
"""
shodan_tool.py
Same functionality as your original file, but API key is loaded
from config_loader (.env) instead of hardcoding the key.
"""

# --- shared config loader: ensure repo root is on sys.path ---
import sys
from pathlib import Path

# Adjust parents[x] based on how deep this file is inside project.
# If file is in: Layer2_Threat_Intel/bhavana/shodan/
# Then parents[2] points to Layer2_Threat_Intel (project root)
project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root))

from config_loader import get_keys
# --------------------------------------------------------------

import shodan
import json

# Output folder
OUTPUT_DIR = project_root / "outputs" / "shodan"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def get_next_filename():
    files = sorted(OUTPUT_DIR.glob("shodan_*.json"))
    return OUTPUT_DIR / f"shodan_{len(files) + 1}.json"


def shodan_ip_lookup():
    keys = get_keys()
    api_key = keys.get("shodan")  # loads SHODAN_API_KEY from .env

    if not api_key:
        print("❌ SHODAN_API_KEY missing in .env")
        return

    ip = input("Enter IP address: ").strip()
    if not ip:
        print("IP required.")
        return

    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip)

        # SAME OUTPUT AS YOUR ORIGINAL CODE
        result = {
            "ip": host.get("ip_str"),
            "country": host.get("country_name"),
            "city": host.get("city"),
            "isp": host.get("isp"),
            "asn": host.get("asn"),
            "org": host.get("org"),
            "open_ports": host.get("ports", [])
        }

    except Exception as e:
        result = {"error": str(e)}

    outfile = get_next_filename()
    outfile.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"✔ Shodan output saved to {outfile}")


if __name__ == "__main__":
    shodan_ip_lookup()
