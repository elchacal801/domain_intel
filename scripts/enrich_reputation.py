#!/usr/bin/env python3
"""
enrich_reputation.py

Adds reputation and age data to domains.
1. Checks DNS RBLs (Spamhaus ZEN, etc.) - simple boolean "listed" check.
2. Queries RDAP for 'creation date' to determine domain age.

Input: CSV with 'domain'
Output: CSV with 'is_rbl_listed', 'creation_date', 'domain_age_days'
Optimized: Higher concurrency with ThreadPoolExecutor map.
"""

import argparse
import csv
import dns.resolver
import requests
import time
import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional
from tqdm import tqdm

# Generic RBLs to check (careful with rate limits on public resolvers)
RBLS = [
    "zen.spamhaus.org",
    "bl.spamcop.net" 
]

def check_rbl(domain: str, resolver) -> List[str]:
    """Returns list of RBLs the domain (or its IP) is listed in."""
    hits = []
    # 1. Domain Block List (DBL) check
    try:
        q = f"{domain}.dbl.spamhaus.org"
        resolver.resolve(q, 'A')
        hits.append("spamhaus_dbl")
    except Exception:
        pass
    return hits

def get_rdap_age(domain: str) -> Dict[str, str]:
    """
    Queries RDAP for creation date.
    Returns {'creation_date': 'YYYY-MM-DD', 'age_days': '123'}
    """
    res = {"creation_date": "", "age_days": ""}
    try:
        # RDAP.org is a handy redirector, or use direct registrar if known.
        # We'll use a public RDAP bootstrap or rdap.org for simplicity.
        # Note: Heavy usage might get rate limited.
        url = f"https://rdap.org/domain/{domain}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            events = data.get("events", [])
            c_date = None
            for e in events:
                if e.get("eventAction") in ("registration", "last changed"): 
                    # 'registration' is best, 'last changed' is fallback
                    if e.get("eventAction") == "registration":
                        c_date = e.get("eventDate")
                        break
            
            if c_date:
                # Format: 2021-01-23T12:34:56Z
                dt = datetime.datetime.strptime(c_date.split('T')[0], "%Y-%m-%d")
                res["creation_date"] = dt.strftime("%Y-%m-%d")
                delta = datetime.datetime.now() - dt
                res["age_days"] = str(delta.days)
    except Exception:
        pass
    
    return res

def process_one(row: Dict) -> Dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    
    domain = row.get("domain", "")
    if not domain:
        return row
        
    # RBL
    hits = check_rbl(domain, resolver)
    row["rbl_hits"] = ";".join(hits)
    
    # RDAP
    # We might want to limit RDAP to only 'suspicious' ones to save API calls
    # or just do all if list is small. 
    rdap = get_rdap_age(domain)
    row["creation_date"] = rdap["creation_date"]
    row["age_days"] = rdap["age_days"]
    
    return row

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/dea_domains_enriched.csv")
    ap.add_argument("--output", default="data/dea_domains_reputation.csv")
    ap.add_argument("--workers", type=int, default=50) 
    args = ap.parse_args()
    
    rows = []
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            fieldnames = reader.fieldnames if reader.fieldnames else []
    except FileNotFoundError:
        print("[!] Input file not found.")
        return
            
    # Add new headers
    new_cols = ["rbl_hits", "creation_date", "age_days"]
    for c in new_cols:
        if c not in fieldnames:
            fieldnames.append(c)
    
    print(f"[*] Processing {len(rows)} domains for reputation/age with {args.workers} workers...")
    
    results = []
    # Use map instead of submitting futures to a list to save memory
    with ThreadPoolExecutor(max_workers=args.workers) as exe:
        # map is lazy-ish, but for lists it might consume. 
        # However, it yields results in order, which is nice.
        # We wrap in list() to consume all, or iterate.
        iterator = exe.map(process_one, rows)
        
        # Wrap with tqdm for progress
        for res in tqdm(iterator, total=len(rows)):
            results.append(res)
            
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
        
    print(f"[*] Done. Saved to {args.output}")

if __name__ == "__main__":
    main()
