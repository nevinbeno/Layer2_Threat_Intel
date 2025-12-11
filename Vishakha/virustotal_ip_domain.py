import requests
import json

API_KEY = "3ed80728e4d4cde21539d8e34c0556dca327f56180980c4276f8b0a36e2f4fdb"

# --------- IP SCAN ---------
ip = "8.8.8.8"
ip_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

headers = {
    "x-apikey": API_KEY
}

ip_response = requests.get(ip_url, headers=headers)

print("Status Code (IP Scan):", ip_response.status_code)

if ip_response.status_code == 200:
    data = ip_response.json()

    attributes = data["data"]["attributes"]

    print("\n--- VirusTotal IP Summary ---")
    print("IP:", ip)
    print("Reputation Score:", attributes.get("reputation"))
    print("Country:", attributes.get("country"))
    print("Owner:", attributes.get("as_owner"))

    print("\nDetected URLs:")
    urls = attributes.get("last_analysis_stats", {})
    print(json.dumps(urls, indent=2))

else:
    print("Error in IP Scan")

# --------- DOMAIN SCAN ---------
domain = "example.com"
domain_url = f"https://www.virustotal.com/api/v3/domains/{domain}"

domain_response = requests.get(domain_url, headers=headers)

print("\nStatus Code (Domain Scan):", domain_response.status_code)

if domain_response.status_code == 200:
    d_data = domain_response.json()

    d_attr = d_data["data"]["attributes"]

    print("\n--- VirusTotal Domain Summary ---")
    print("Domain:", domain)
    print("Reputation:", d_attr.get("reputation"))
    print("Categories:", d_attr.get("categories"))
    print("Country:", d_attr.get("country"))

    print("\nLast Analysis Stats:")
    print(json.dumps(d_attr.get("last_analysis_stats"), indent=2))

else:
    print("Error in Domain Scan")
