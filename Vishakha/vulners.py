import requests

API_KEY = "YOUR_API_KEY"
CVE_ID = "CVE-2023-1234"

def vulners_lookup():
    url = "https://vulners.com/api/v3/search/id/"
    payload = {
        "id": CVE_ID,
        "apiKey": API_KEY
    }

    response = requests.post(url, json=payload)

    if response.status_code == 200:
        result = response.json()
        return result.get("data", {})
    else:
        return {"error": "Failed to fetch data from Vulners"}

if __name__ == "__main__":
    print(vulners_lookup())
