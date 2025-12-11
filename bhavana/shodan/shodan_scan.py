# shodan_tool.py
import shodan
import json
from pathlib import Path

OUTPUT_DIR = Path("outputs/shodan")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def get_next_filename():
    files = sorted(OUTPUT_DIR.glob("shodan_*.json"))
    return OUTPUT_DIR / f"shodan_{len(files) + 1}.json"

def shodan_ip_lookup():
    api_key = "YWdyNIz4w7w1hYFDiZ4ON9tD4V0aAdpX"
    ip = input("Enter IP address: ").strip()
    if not api_key or not ip:
        print("API key and IP required.")
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
            "open_ports": host.get("ports", [])
        }
    except Exception as e:
        result = {"error": str(e)}

    outfile = get_next_filename()
    outfile.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"✔ Shodan output saved to {outfile}")

if __name__ == "__main__":
    shodan_ip_lookup()
