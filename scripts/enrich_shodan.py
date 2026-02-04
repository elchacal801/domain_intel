#!/usr/bin/env python3
"""
enrich_shodan.py

Enriches domain data with Shodan intelligence.
1. Resolves Domain -> IP (if missing).
2. Queries Shodan for IP details (Ports, Vulns, Tags).
3. Adds intelligence to CSV.
"""

import argparse
import csv
import os
import sys
import logging
import asyncio
import socket
from typing import Dict, List, Set
from dotenv import load_dotenv
import shodan

# Setup Logging
logging.basicConfig(level=logging.INFO, format='[*] %(message)s')
log = logging.info

def resolve_domain(domain: str) -> str:
    """Resolves A record for a domain."""
    try:
        return socket.gethostbyname(domain)
    except:
        return ""

def process_shodan(api_key: str, domains: List[Dict], output_file: str):
    try:
        api = shodan.Shodan(api_key)
    except Exception as e:
        log(f"Failed to init Shodan API: {e}")
        return

    # 1. Gather IPs
    log(f"Resolving IPs for {len(domains)} domains...")
    ip_map = {} # ip -> [domains]
    
    unique_ips = set()
    
    for row in domains:
        domain = row.get("domain")
        if not domain: continue
        
        # Prefer existing IP if available
        ip = row.get("mx_ip") or row.get("a_record") 
        
        # If no handy IP, resolve it
        if not ip or ip == "":
            ip = resolve_domain(domain)
            
        if ip:
            unique_ips.add(ip)
            if ip not in ip_map: ip_map[ip] = []
            ip_map[ip].append(row)
            
    log(f"Found {len(unique_ips)} unique IPs to scan.")

    # 2. Query Shodan (Concurrent)
    log(f"Scanning {len(unique_ips)} unique IPs with 5 workers...")
    
    unique_ips_list = list(unique_ips)
    shodan_results = {}
    
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def scan_ip(ip):
        try:
            host_info = api.host(ip, minify=True) # minify to save bandwidth
            return ip, host_info
        except Exception:
            return ip, None

    with ThreadPoolExecutor(max_workers=5) as executor: # Conservative worker count for rate limits
        future_map = {executor.submit(scan_ip, ip): ip for ip in unique_ips_list}
        
        count = 0
        total = len(unique_ips_list)
        
        for future in as_completed(future_map):
            count += 1
            if count % 10 == 0:
                print(f"[*] Progress: {count}/{total}", end='\r')
                
            ip, info = future.result()
            if info:
                s_data = {
                    "ip": ip,
                    "ports": ";".join([str(p) for p in info.get("ports", [])]),
                    "tags": ";".join(info.get("tags", [])),
                    "os": info.get("os", "") or "",
                    "hostnames": ";".join(info.get("hostnames", [])),
                    "vulns": ";".join(info.get("vulns", []))
                }
                shodan_results[ip] = s_data

    print("\n[*] Shodan scan complete.")

    # Map back to results
    for row in domains:
        # Resolve IP again or use what we solved earlier? 
        # Ideally we use the map we built
        # But 'domains' is just a list of dicts. We need to match efficiently.
        # We can re-use the ip_map logic to be safe, but we already have ip_map from step 1
        pass 
        
    results = []
    # Using ip_map from Step 1 to distribute results
    for ip, rows in ip_map.items():
        s_data = shodan_results.get(ip)
        
        for r in rows:
            enriched = r.copy()
            if s_data:
                enriched["shodan_ip"] = ip
                enriched.update(s_data)
            else:
                enriched["shodan_ip"] = ip
                # Add empty fields
                enriched["ports"] = ""
                enriched["vulns"] = ""
                enriched["tags"] = ""
                enriched["os"] = ""
                enriched["hostnames"] = ""
            results.append(enriched)
    
    # 3. Write Output
    if not results:
        log("No results found.")
        return

    # Collect all unique keys from all rows to ensure coverage
    all_keys = set()
    for r in results:
        all_keys.update(r.keys())
    headers = sorted(list(all_keys))
    
    # Optional: prioritize 'domain', 'ip', 'shodan_ip' at the start
    priority = ['domain', 'ip', 'shodan_ip']
    for p in reversed(priority):
        if p in headers:
            headers.insert(0, headers.pop(headers.index(p)))

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(results)
        
    log(f"Wrote {len(results)} rows to {output_file}")


def main():
    load_dotenv()
    API_KEY = os.getenv("SHODAN_API_KEY")
    if not API_KEY:
        log("Error: SHODAN_API_KEY not found in .env")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/dea_domains_probed.csv")
    parser.add_argument("--output", default="data/shodan_intelligence.csv")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    # Read Input
    domains = []
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                domains.append(row)
    except FileNotFoundError:
        log("Input file not found.")
        sys.exit(1)

    if args.limit > 0:
        domains = domains[:args.limit]

    process_shodan(API_KEY, domains, args.output)

if __name__ == "__main__":
    main()
