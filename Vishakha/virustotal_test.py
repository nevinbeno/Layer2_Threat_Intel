import requests

api_key = "3ed80728e4d4cde21539d8e34c0556dca327f56180980c4276f8b0a36e2f4fdb"
hash_value = "44d88612fea8a8f36de82e1278abb02f"  # test hash

url = f"https://www.virustotal.com/api/v3/files/{hash_value}"

headers = {
    "x-apikey": api_key
}

response = requests.get(url, headers=headers)

print("Status Code:", response.status_code)
print("Output JSON:")
print(response.json())

data = response.json()

attributes = data["data"]["attributes"]

print("\n--- VirusTotal Summary ---")
print("MD5:", attributes.get("md5"))
print("SHA1:", attributes.get("sha1"))
print("SHA256:", attributes.get("sha256"))
print("File Type:", attributes.get("type_description"))

stats = attributes.get("last_analysis_stats", {})
print("\n--- Detection Stats ---")
print("Malicious:", stats.get("malicious"))
print("Suspicious:", stats.get("suspicious"))
print("Undetected:", stats.get("undetected"))
print("Harmless:", stats.get("harmless"))
