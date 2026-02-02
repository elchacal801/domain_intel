#!/usr/bin/env python3
"""
shodan_pivot.py

Pivots from visual fingerprints to finding new infrastructure.
1. Reads favicon hashes from data/visual_hashes.csv
2. Searches Shodan for 'http.favicon.hash:<hash>'
3. Saves discovered IPs/Domains to data/shodan_pivots.csv
"""

import argparse
import csv
import os
import sys
import logging
import time
from typing import Dict, List, Set
from dotenv import load_dotenv
import shodan

# Setup Logging
logging.basicConfig(level=logging.INFO, format='[*] %(message)s')
log = logging.info

def process_pivots(api_key: str, input_file: str, output_file: str):
    try:
        api = shodan.Shodan(api_key)
    except Exception as e:
        log(f"Failed to init Shodan API: {e}")
        return

    # 1. Read Hashes via CSV
    hashes = set()
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                h = row.get("favicon_hash")
                if h and h != "0" and h != "":
                    hashes.add(h)
    except FileNotFoundError:
        log(f"Input file {input_file} not found. Run visual_fingerprint.py first?")
        return
        
    log(f"Found {len(hashes)} unique favicon hashes to pivot on.")
    
    results = []
    
    # 2. Search Shodan
    for h in hashes:
        query = f"http.favicon.hash:{h}"
        log(f"Searching Shodan for {query}...")
        
        try:
            # Search API returns matches
            search_res = api.search(query)
            total = search_res.get('total', 0)
            log(f"  -> Found {total} matches.")
            
            for match in search_res.get('matches', []):
                res = {
                    "pivot_hash": h,
                    "measure": "http.favicon.hash",
                    "ip": match.get('ip_str'),
                    "port": match.get('port'),
                    "org": match.get('org'),
                    "asn": match.get('asn'),
                    "domains": ";".join(match.get('hostnames', []))
                }
                results.append(res)
                
            time.sleep(1) # Rate limit safety
            
        except shodan.APIError as e:
            log(f"  [!] API Error: {e}")
        except Exception as e:
            log(f"  [!] Error: {e}")
            
    # 3. Write Output
    if not results:
        log("No pivot results found.")
        return

    headers = ["pivot_hash", "measure", "ip", "port", "org", "asn", "domains"]
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(results)
        
    log(f"Wrote {len(results)} pivots to {output_file}")


def main():
    load_dotenv()
    API_KEY = os.getenv("SHODAN_API_KEY")
    if not API_KEY:
        log("Error: SHODAN_API_KEY not found in .env")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/visual_hashes.csv")
    parser.add_argument("--output", default="data/shodan_pivots.csv")
    args = parser.parse_args()

    process_pivots(API_KEY, args.input, args.output)

if __name__ == "__main__":
    main()
