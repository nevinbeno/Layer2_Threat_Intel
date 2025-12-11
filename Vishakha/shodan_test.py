import requests
import json

SHODAN_API_KEY = "YOUR_SHODAN_KEY"
ip = "8.8.8.8"  # sample IP

url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
response = requests.get(url)

print("Status Code:", response.status_code)

if response.status_code == 200:
    data = response.json()

    print("\n--- Shodan Summary ---")
    print("IP:", data.get("ip_str"))
    print("Organization:", data.get("org"))
    print("ISP:", data.get("isp"))
    print("Country:", data.get("country_name"))
    print("\nOpen Ports:", data.get("ports"))

    print("\n--- Full JSON (Pretty Printed) ---")
    print(json.dumps(data, indent=2))

else:
    print("Error:", response.status_code)
