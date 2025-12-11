import requests
import json
import os

# ---------------------------
# CONFIG: ADD YOUR API KEYS
# ---------------------------
SHODAN_API_KEY = "6nVnxyiNFadecnjUqeJWbEGlf0ub8lOz"
VT_API_KEY = "3ed80728e4d4cde21539d8e34c0556dca327f56180980c4276f8b0a36e2f4fdb"
VULNERS_API_KEY = ""   # optional

# ---------------------------
# 1️⃣ SHODAN SCAN
# ---------------------------
def scan_shodan(ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url)
        return response.json()
    except Exception as e:
        return {"exception": str(e)}

# ---------------------------
# 2️⃣ VIRUSTOTAL SCAN
# ---------------------------
def scan_virustotal(file_hash):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(url, headers=headers)
        return response.json()
    except Exception as e:
        return {"exception": str(e)}

# ---------------------------
# 3️⃣ CISA KEV FEED
# ---------------------------
def fetch_cisa_kev():
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url)
        return response.json()
    except Exception as e:
        return {"exception": str(e)}

# ---------------------------
# 4️⃣ VULNERS SCAN (OPTIONAL)
# ---------------------------
def scan_vulners():
    try:
        url = "https://vulners.com/api/v3/burp/software/"
        payload = {
            "os": "windows",
            "software": "openssl",
            "version": "1.1.1"
        }
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=payload, headers=headers)
        return response.json()
    except Exception as e:
        return {"exception": str(e)}

# ---------------------------
# 5️⃣ SAVE JSON OUTPUT
# ---------------------------
def save_to_json(filename, data):
    try:
        os.makedirs("outputs", exist_ok=True)
        filepath = os.path.join("outputs", filename)

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        print(f"📁 Results saved to {filepath}")
    except Exception as e:
        print("❌ Error saving JSON:", e)

# ---------------------------
# 6️⃣ MAIN EXECUTION
# ---------------------------
def main():
    print("\n==============================")
    print("  🔥 THREAT INTELLIGENCE TOOL")
    print("==============================")

    results = {}

    # Shodan
    ip = input("\nEnter IP to scan with Shodan: ")
    results["shodan"] = scan_shodan(ip)
    print("✅ Shodan scan completed")

    # VirusTotal
    file_hash = input("\nEnter file hash for VirusTotal scan: ")
    results["virustotal"] = scan_virustotal(file_hash)
    print("✅ VirusTotal scan completed")

    # CISA KEV
    print("\nFetching CISA KEV...")
    results["cisa_kev"] = fetch_cisa_kev()
    print("✅ CISA KEV fetched")

    # Vulners
    print("\nRunning Vulners scan...")
    results["vulners"] = scan_vulners()
    print("✅ Vulners scan completed")

    # Save JSON only
    save_to_json("threat_intel_output.json", results)

    print("\n✔ All modules executed successfully!")

# ---------------------------
# RUN SCRIPT
# ---------------------------
if __name__ == "__main__":
    main()
