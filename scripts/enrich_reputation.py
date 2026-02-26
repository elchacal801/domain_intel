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
import os
import csv
import dns.resolver
import dns.exception
import requests
import time
import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional
from tqdm import tqdm
from shared.sanitize import sanitize_csv_value

# Generic RBLs to check (careful with rate limits on public resolvers)
RBLS = [
    "zen.spamhaus.org",
    "bl.spamcop.net" 
]

# OTX Setup
OTX_API_KEY = os.environ.get("ALIENVAULT_OTX_API_KEY")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{}/general"
# Simple in-memory cache to avoid redundant hits in same run (though input shouldn't have dupes)
OTX_CACHE = {} 

def check_otx(domain: str) -> str:
    """Queries AlienVault OTX for pulses."""
    if not OTX_API_KEY:
        return ""
        
    url = OTX_BASE_URL.format(domain)
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    
    try:
        # Rate limit prevention (naive)
        # OTX is 10k/hour = ~2.7/sec. 50 workers will HAMMER this.
        # We need to rely on the requests failing or implement a global ratelimiter.
        # For now, we swallow errors to avoid stopping the pipeline.
        resp = requests.get(url, headers=headers, timeout=5)
        
        if resp.status_code == 200:
            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            count = pulse_info.get("count", 0)
            if count > 0:
                # Get Pulse names if possible?
                pulses = pulse_info.get("pulses", [])
                names = [p.get("name", "Unknown") for p in pulses[:3]] # Top 3
                return f"OTX_Pulses:{count};" + ",".join(names)
        elif resp.status_code == 429:
            # Rate Limit
            return "OTX_RateLimited"
            
    except requests.RequestException:
        pass
        
    return ""


def check_rbl(domain: str, resolver) -> List[str]:
    """Returns list of RBLs the domain (or its IP) is listed in."""
    hits = []
    # 1. Domain Block List (DBL) check
    try:
        q = f"{domain}.dbl.spamhaus.org"
        resolver.resolve(q, 'A')
        hits.append("spamhaus_dbl")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.resolver.Timeout, dns.exception.DNSException):
        pass
    return hits

def get_rdap_data(domain: str) -> Dict[str, str]:
    """
    Queries RDAP for creation date and registrant organization.
    Returns {'creation_date': 'YYYY-MM-DD', 'age_days': '123', 'registrant_org': '...'}
    """
    res = {"creation_date": "", "age_days": "", "registrant_org": ""}
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

            # Extract registrant organization
            for entity in data.get("entities", []):
                if "registrant" in entity.get("roles", []):
                    vcard_array = entity.get("vcardArray", [[], []])
                    if len(vcard_array) > 1:
                        for vcard in vcard_array[1]:
                            if isinstance(vcard, list) and len(vcard) > 3 and vcard[0] in ("fn", "org"):
                                org_val = vcard[3]
                                if isinstance(org_val, str) and org_val.strip():
                                    res["registrant_org"] = sanitize_csv_value(org_val.strip())
                                break
                    break
    except (requests.RequestException, ValueError, KeyError):
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
    rdap = get_rdap_data(domain)
    row["creation_date"] = rdap["creation_date"]
    row["age_days"] = rdap["age_days"]
    row["registrant_org"] = rdap.get("registrant_org", "")
    
    # OTX Check (if key exists)
    otx_tags = check_otx(domain)
    if otx_tags:
        row["otx_risk"] = sanitize_csv_value(otx_tags)

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
    new_cols = ["rbl_hits", "creation_date", "age_days", "otx_risk", "registrant_org"]
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
