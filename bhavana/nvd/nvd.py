import requests
import json
import os
import csv

NVD_API_KEY = "5e12e3ec-0fb2-477c-91ce-36b95fc6d6e6"

# ---------- CLEAN REFERENCE FILTER ----------
ALLOWED_DOMAINS = [
    "microsoft.com", "oracle.com", "redhat.com", "apple.com",
    "cisco.com", "vmware.com", "paloaltonetworks.com"
]


def extract_short_info(data):
    """Extract only important NVD fields for a clean short output."""
    try:
        item = data["vulnerabilities"][0]["cve"]

        desc = item["descriptions"][0]["value"]
        published = item.get("published", "Unknown")

        # CWE
        cwe = "Unknown"
        if item.get("weaknesses"):
            cwe_description = item["weaknesses"][0].get("description", [])
            if cwe_description:
                cwe = cwe_description[0]["value"]

        # Filter references
        refs = [
            r["url"]
            for r in item.get("references", [])
            if any(domain in r["url"] for domain in ALLOWED_DOMAINS)
        ]

        # Always include the official NVD page
        refs.insert(0, f"https://nvd.nist.gov/vuln/detail/{item['id']}")

        # Severity + Score
        severity = "Unknown"
        score = None
        metrics = item.get("metrics", {})

        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss["baseSeverity"]
            score = cvss["baseScore"]
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]
            severity = cvss["baseSeverity"]
            score = cvss["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]
            severity = cvss["baseSeverity"]
            score = cvss["baseScore"]

        return {
            "cve_id": item["id"],
            "severity": severity,
            "score": score,
            "published": published,
            "description": desc,
            "cwe": cwe,
            "references": refs
        }

    except Exception as e:
        return {"error": f"Parsing error: {e}"}


def lookup_cve(cve_id):
    """Fetch NVD record for a CVE."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=20)
    except Exception as e:
        return None, f"Request failed: {e}"

    if response.status_code != 200:
        return None, f"HTTP {response.status_code}"

    data = response.json()

    if not data.get("vulnerabilities"):
        return None, "No data found"

    return data, None


def save_short_json(cve_id, clean_data):
    folder = "nvd_output"
    os.makedirs(folder, exist_ok=True)

    file_name = f"nvd_{cve_id.replace('-', '_')}.json"
    path = os.path.join(folder, file_name)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(clean_data, f, indent=4)

    return path


# ---------- NEW FEATURE: PROCESS CSV ----------
def process_csv(csv_file):
    results = []
    print("\n📄 Reading CSV...")

    with open(csv_file, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve = row["cve_id"].strip()
            print(f"\n🔍 Checking: {cve}")

            data, error = lookup_cve(cve)
            if error:
                print(f"❌ Error for {cve}: {error}")
                continue

            clean_info = extract_short_info(data)
            save_short_json(cve, clean_info)
            results.append(clean_info)

    # Save combined CSV summary
    summary_path = "nvd_output/nvd_combined_summary.csv"
    keys = ["cve_id", "severity", "score", "published", "cwe"]

    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for item in results:
            writer.writerow({k: item.get(k) for k in keys})

    print(f"\n📁 Combined summary saved as: {summary_path}")


# ---------- MAIN ----------
if __name__ == "__main__":
    print("=== NVD Tool: Single or Multiple CVE Lookup ===")
    print("1) Check one CVE")
    print("2) Upload CSV file of CVEs\n")

    choice = input("Enter choice (1 or 2): ").strip()

    if choice == "1":
        cve_id = input("Enter CVE ID: ").strip()
        data, error = lookup_cve(cve_id)

        if error:
            print(f"\n❌ Error: {error}")
            exit()

        clean_info = extract_short_info(data)
        out = save_short_json(cve_id, clean_info)

        print(f"\n📁 Clean JSON saved: {out}")

    elif choice == "2":
        csv_file = input("Enter CSV file name (example: cves.csv): ")
        process_csv(csv_file)

    else:
        print("Invalid choice.")
