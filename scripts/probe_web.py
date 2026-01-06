#!/usr/bin/env python3
"""
probe_web.py

Active fingerprinting of domains via HTTP/S.
- Random User-Agents
- Follows redirects (limit)
- Captures Status, Title, Server

Usage:
  python probe_web.py --input data/dea_domains_reputation.csv --output data/dea_domains_probed.csv --proxy socks5://localhost:9050
"""

import argparse
import csv
import requests
import re
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

def get_title(html: str) -> str:
    if not html: return ""
    m = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()[:100] # Limit length
    return ""

def probe(domain: str, proxies: dict) -> dict:
    res = {
        "http_status": "",
        "http_title": "",
        "http_server": "",
        "https_status": "",
        "https_title": "",
        "https_server": ""
    }
    
    ua = random.choice(USER_AGENTS)
    headers = {"User-Agent": ua}
    
    # Try HTTPS first (most common now)
    try:
        r = requests.get(f"https://{domain}", headers=headers, proxies=proxies, timeout=5, verify=False)
        res["https_status"] = str(r.status_code)
        res["https_server"] = r.headers.get("Server", "")
        res["https_title"] = get_title(r.text)
    except Exception:
        pass
        
    # Try HTTP
    try:
        r = requests.get(f"http://{domain}", headers=headers, proxies=proxies, timeout=5)
        res["http_status"] = str(r.status_code)
        res["http_server"] = r.headers.get("Server", "")
        res["http_title"] = get_title(r.text)
    except Exception:
        pass
        
    return res

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/dea_domains_reputation.csv")
    ap.add_argument("--output", default="data/dea_domains_probed.csv")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--proxy", help="Proxy URL (e.g. socks5://localhost:9050)")
    
    args = ap.parse_args()
    
    proxies = {}
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}
        print(f"[*] Using proxy: {args.proxy}")
        
    rows = []
    # If input doesn't exist, we might be running strictly probe without enrichment.
    # But usually we chain them. check file.
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            fieldnames = reader.fieldnames
    except FileNotFoundError:
        print(f"[!] Input {args.input} not found.")
        return

    new_cols = ["http_status", "http_title", "http_server", "https_status", "https_title", "https_server"]
    for c in new_cols:
        if c not in fieldnames:
            fieldnames.append(c)
            
    print(f"[*] Probing {len(rows)} domains...")
    
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as exe:
        futures = {exe.submit(probe, r["domain"], proxies): r for r in rows}
        
        for fut in as_completed(futures):
            org_row = futures[fut]
            try:
                data = fut.result()
                org_row.update(data)
            except:
                pass
            results.append(org_row)
            
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
        
    print(f"[*] Done. Saved to {args.output}")

if __name__ == "__main__":
    main()
