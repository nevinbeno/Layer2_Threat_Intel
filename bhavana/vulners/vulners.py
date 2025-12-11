# vulners_slim.py
# Minimal, practical Vulners Lucene search -> simplified JSON saved to outputs/vulners/vulners_<n>.json

import requests, json
from pathlib import Path
from datetime import datetime

LUCENE = "https://vulners.com/api/v3/search/lucene"
OUTDIR = Path("outputs/vulners")
OUTDIR.mkdir(parents=True, exist_ok=True)

def next_file():
    files = sorted(OUTDIR.glob("vulners_*.json"))
    return OUTDIR / f"vulners_{len(files) + 1}.json"

def call_lucene(key, q):
    headers = {"X-Api-Key": key, "Content-Type": "application/json"}
    body = {"query": q, "size": 10}   # you can increase size if needed
    return requests.post(LUCENE, headers=headers, json=body, timeout=20)

def simplify_lucene_json(j):
    out = {"query_time": datetime.utcnow().isoformat() + "Z", "total_results": 0, "results": []}
    data = j.get("data") or {}
    # two common shapes: data.search (your debug) or top-level results
    hits = []
    if isinstance(data, dict) and data.get("search"):
        hits = data.get("search", [])
    elif isinstance(j.get("results"), list):
        hits = j.get("results", [])
    else:
        # try older shape: j.get('data').get('results')
        hits = data.get("results", []) if isinstance(data, dict) else []

    for hit in hits:
        src = hit.get("_source") if isinstance(hit, dict) else hit
        if not src:
            src = hit  # fallback
        title = src.get("title") or src.get("name") or hit.get("title")
        published = src.get("published")
        typ = src.get("type") or hit.get("type")
        # try CVE list
        cves = src.get("cvelist") or src.get("cves") or src.get("cve") or []
        # cvss - try a few common spots
        cvss = None
        cvss3 = src.get("cvss3") or {}
        if isinstance(cvss3, dict):
            v = cvss3.get("cvssV31") or cvss3.get("cvssV30")
            if isinstance(v, dict):
                cvss = v.get("baseScore") or v.get("base_score")
        if not cvss:
            cvss = src.get("cvss") or src.get("cvssScore")
        desc = src.get("description") or ""
        # shorten description
        desc_short = (desc[:500] + "...") if desc and len(desc) > 500 else desc

        out["results"].append({
            "title": title,
            "published": published,
            "type": typ,
            "cvss": cvss,
            "cve_ids": cves,
            "description": desc_short
        })
    out["total_results"] = len(out["results"])
    return out

def main():
    key ="NJ98SGKMN33VNHOY2CFU19D2PGN0RG6TAE26TICW28BJ2W7WZ5WODDEGZGKHZY01"
    q = input("Enter CVE or keyword (e.g. windows rce or CVE-2021-44228): ").strip()
    if not key or not q:
        print(json.dumps({"error":"API key and query required"}, indent=2)); return

    try:
        resp = call_lucene(key, q)
    except Exception as e:
        print(json.dumps({"error":f"network error: {e}"}, indent=2)); return

    if resp.status_code != 200:
        # print short helpful error
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        print(json.dumps({"http_status": resp.status_code, "error": str(body)}, indent=2))
        return

    try:
        j = resp.json()
    except Exception:
        print(json.dumps({"error":"Invalid JSON response"}, indent=2)); return

    simple = simplify_lucene_json(j)
    outpath = next_file()
    outpath.write_text(json.dumps(simple, indent=2, ensure_ascii=False), encoding="utf-8")

    # Console short summary
    print(f"\nSaved {simple['total_results']} result(s) to {outpath}")
    if simple["total_results"] > 0:
        r = simple["results"][0]
        print("Top result:", r.get("title"), "| CVE(s):", r.get("cve_ids"), "| CVSS:", r.get("cvss"))
    else:
        print("No results found for query. Try a different keyword or a CVE ID (e.g. CVE-2021-44228).")

if __name__ == "__main__":
    main()
