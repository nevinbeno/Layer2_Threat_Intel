import requests
import json

# ---------- SHODAN TEST ----------
SHODAN_API_KEY = "YOUR_SHODAN_KEY"
ip = "8.8.8.8"

url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
response = requests.get(url)

if response.status_code == 200:
    data = response.json()
    print("Shodan JSON Output:")
    print(json.dumps(data, indent=2))
else:
    print(f"Error: {response.status_code}")


# ---------- VIRUSTOTAL TEST ----------
headers = {"x-apikey": "3ed80728e4d4cde21539d8e34c0556dca327f56180980c4276f8b0a36e2f4fdb"}
file_hash = "44d88612fea8a8f36de82e1278abb02f"  # example file hash

vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
vt_response = requests.get(vt_url, headers=headers)

if vt_response.status_code == 200:
    vt_data = vt_response.json()
    print("\nVirusTotal JSON Output:")
    print(json.dumps(vt_data, indent=2))
else:
    print(f"VirusTotal Error: {vt_response.status_code}")
