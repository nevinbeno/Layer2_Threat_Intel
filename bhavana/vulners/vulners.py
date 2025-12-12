#!/usr/bin/env python3
"""
vulners_slim.py

Slim Vulners Lucene search tool using central config_loader.py
so all API keys come from a shared .env in the project root.
"""

# --- shared config loader: ensure repo root is on sys.path ---
import sys
from pathlib import Path

# adjust depth if your folder structure differs (usually parents[2] is correct)
project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root))

from config_loader import get_keys
# -------------------------------------------------------------

import requests
import json
from datetime import datetime

# Load API key from .env (key name: VULNERS_API_KEY)
keys = get_keys()
VULNERS_KEY = keys.get("vulners")   # Must match your .env

# Vulners API endpoint
LUCENE = "https://vulners.com/api/v3/search/lucene"

# Output folder inside repo
OUTDIR = project_root / "outputs" / "vulners"
OUTDIR.mkdir(parents=True, exist_ok=True)


# ---------- FILENAME UTILITY ----------
def next_file():
    files = sorted(OUTDIR.glob("vulners_*.json"))
    return OUTDIR / f"vulners_{len(files) + 1}.json"


# ---------- API CALL ----------
def call_lucene(api_key, query):
    headers = {"X-Api-Key": api_key, "Content-Type": "application/json"}
    body = {"query": query, "size": 10}

    return requests.post(LUCENE, headers=headers, json=body, timeout=20)


# ---------- JSON SIMPLIFIER ----------
def simplify_lucene_json(j):
    out = {
        "query_time": datetime.utcnow().isoformat() + "Z",
        "total_results": 0,
        "results": []
    }

    data = j.get("data") or {}
    hits = []

    # Handle common Vulners response shapes
    if isinstance(data, dict) and data.get("search"):
        hits = data.get("search", [])
    elif isinstance(j.get("results"), list):
        hits = j.get("results", [])
    else:
        hits = data.get("results", []) if isinstance(data, dict) else []

    for hit in hits:
        src = hit.get("_source") if isinstance(hit, dict) else hit
        if not src:
            src = hit

        title = src.get("title") or src.get("name") or hit.get("title")
        published = src.get("published")
        typ = src.get("type") or hit.get("type")

        # CVE Lists
        cves = src.get("cvelist") or src.get("cves") or src.get("cve") or []

        # CVSS score
        cvss = None
        cvss3 = src.get("cvss3") or {}
        if isinstance(cvss3, dict):
            v = cvss3.get("cvssV31") or cvss3.get("cvssV30")
            if isinstance(v, dict):
                cvss = v.get("baseScore") or v.get("base_score")

        if not cvss:
            cvss = src.get("cvss") or src.get("cvssScore")

        desc = src.get("description") or ""
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


# ---------- MAIN ----------
def main():
    if not VULNERS_KEY:
        print(json.dumps({"error": "Missing Vulners API key. Set VULNERS_API_KEY in .env"}, indent=2))
        return

    query = input("Enter CVE or keyword (e.g. 'windows rce' or 'CVE-2021-44228'): ").strip()
    if not query:
        print(json.dumps({"error": "Query required"}, indent=2))
        return

    try:
        resp = call_lucene(VULNERS_KEY, query)
    except Exception as e:
        print(json.dumps({"error": f"Network error: {e}"}, indent=2))
        return

    if resp.status_code != 200:
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        print(json.dumps({"http_status": resp.status_code, "error": str(body)}, indent=2))
        return

    try:
        j = resp.json()
    except Exception:
        print(json.dumps({"error": "Invalid JSON response"}, indent=2))
        return

    simplified = simplify_lucene_json(j)
    outpath = next_file()

    outpath.write_text(json.dumps(simplified, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nSaved {simplified['total_results']} result(s) to {outpath}")

    if simplified["total_results"] > 0:
        top = simplified["results"][0]
        print("Top result:", top.get("title"), "| CVE(s):", top.get("cve_ids"), "| CVSS:", top.get("cvss"))
    else:
        print("No results found — try a different keyword or a known CVE ID (e.g. CVE-2021-44228).")


if __name__ == "__main__":
    main()
