#!/usr/bin/env python3
"""
shodan_tool.py
Secure Shodan IP lookup (reads SHODAN_API_KEY from repo .env via config_loader).
Usage:
  python shodan_tool.py 1.2.3.4
  python shodan_tool.py     # interactive prompt
"""

# --- shared config loader: ensure repo root is on sys.path ---
import sys
from pathlib import Path

# adjust parents[n] if your file depth differs. parents[2] points to project root if file is at bhavana/shodan/
project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root))

from config_loader import get_keys
# ----------------------------------------------------------

import shodan
import json

OUTPUT_DIR = project_root / "outputs" / "shodan"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def get_next_filename():
    files = sorted(OUTPUT_DIR.glob("shodan_*.json"))
    return OUTPUT_DIR / f"shodan_{len(files) + 1}.json"

def shodan_ip_lookup(ip: str | None = None):
    keys = get_keys()
    api_key = keys.get("shodan")

    if not api_key:
        print("❌ Error: Shodan API key not found. Add SHODAN_API_KEY to your .env file in the project root.")
        return

    if not ip:
        ip = input("Enter IP address: ").strip()

    if not ip:
        print("❌ IP address is required.")
        return

    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip)

        result = {
            "ip": host.get("ip_str"),
            "country": host.get("country_name"),
            "city": host.get("city"),
            "isp": host.get("isp"),
            "asn": host.get("asn"),
            "org": host.get("org"),
            "open_ports": host.get("ports", []),
            "data": host.get("data", [])  # raw banner/service data
        }

    except shodan.exception.APIError as api_err:
        result = {"error": f"Shodan API error: {api_err}"}
    except Exception as e:
        result = {"error": str(e)}

    outfile = get_next_filename()
    outfile.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"✔ Shodan output saved to: {outfile}")

def main():
    import sys as _sys
    ip_arg = None
    if len(_sys.argv) > 1:
        ip_arg = _sys.argv[1].strip()
    shodan_ip_lookup(ip_arg)

if __name__ == "__main__":
    main()
