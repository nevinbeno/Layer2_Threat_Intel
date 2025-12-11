import requests
import json
import os

# ---------------------------
# CONFIG: ADD YOUR API KEYS
# ---------------------------
SHODAN_API_KEY = "key"
VT_API_KEY = "key"
VULNERS_API_KEY = ""   # optional

# ---------------------------
# 1️⃣ SHODAN SCAN
# ---------------------------
def scan_shodan(ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": response.status_code}
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
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": response.status_code}
    except Exception as e:
        return {"exception": str(e)}

# ---------------------------
# 3️⃣ CISA KEV FEED
# ---------------------------
def fetch_cisa_kev():
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": response.status_code}
    except Exception as e:
        return {"exception": str(e)}

# ---------------------------
# 4️⃣ VULNERS SCAN (OPTIONAL)
# ---------------------------
def scan_vulners():
    try:
        # Example payload, can be customized
        url = "https://vulners.com/api/v3/burp/software/"
        payload = {
            "os": "windows",
            "software": "openssl",
            "version": "1.1.1"
        }
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": response.status_code}
    except Exception as e:
        return {"exception": str(e)}

# ---------------------------
# 5️⃣ SAVE JSON OUTPUT
# ---------------------------
def save_to_json(filename, data):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\n📁 Results saved to {filename}")
    except Exception as e:
        print("\n❌ Error saving JSON:", e)

# ---------------------------
# 6️⃣ GENERATE TXT REPORT
# ---------------------------
def generate_report(filename, results):
    try:
        with open(filename, "w") as f:
            f.write("======= THREAT INTELLIGENCE REPORT =======\n\n")

            f.write("----- SHODAN RESULT -----\n")
            f.write(json.dumps(results.get("shodan", {}), indent=2))
            f.write("\n\n")

            f.write("----- VIRUSTOTAL RESULT -----\n")
            f.write(json.dumps(results.get("virustotal", {}), indent=2))
            f.write("\n\n")

            f.write("----- CISA KEV DATA -----\n")
            f.write(json.dumps(results.get("cisa_kev", {}), indent=2))
            f.write("\n\n")

            f.write("----- VULNERS RESULT -----\n")
            f.write(json.dumps(results.get("vulners", {}), indent=2))
            f.write("\n\n")

        print(f"📄 Report saved to {filename}")
    except Exception as e:
        print("\n❌ Error generating report:", e)

# ---------------------------
# 7️⃣ MAIN EXECUTION
# ---------------------------
def main():
    print("\n==============================")
    print("  🔥 THREAT INTELLIGENCE TOOL")
    print("==============================")

    results = {
        "shodan": {},
        "virustotal": {},
        "cisa_kev": {},
        "vulners": {}
    }

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

    # Vulners (optional)
    print("\nRunning Vulners scan...")
    results["vulners"] = scan_vulners()
    print("✅ Vulners scan completed")

    # Save JSON
    save_to_json("threat_intel_output.json", results)

    # Generate TXT report
    generate_report("threat_intel_report.txt", results)

    print("\n✔ All modules executed and reports created successfully!")

# ---------------------------
# RUN SCRIPT
# ---------------------------
if __name__ == "__main__":
    main()

