#!/usr/bin/env python3
"""
enrich_shodan.py

Enriches domain data with Shodan intelligence.
1. Resolves Domain -> IP (if missing).
2. Queries Shodan IP info (Ports, Vulns, Tags) with Caching & Budgeting.
3. Adds intelligence to CSV.
"""

import argparse
import csv
import os
import sys
import logging
import socket
import time
from typing import Dict, List, Optional
from dotenv import load_dotenv
import shodan

from shodan_utils import CreditBudget, ShodanCache

# Setup Logging
logging.basicConfig(level=logging.INFO, format='[*] %(message)s')
log = logging.getLogger("enrich_shodan")
log.setLevel(logging.INFO)

def resolve_domain(domain: str) -> str:
    """Resolves A record for a domain."""
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.timeout, OSError):
        return ""

def process_shodan(api_key: str, domains: List[Dict], output_file: str, budget: int):
    # Init Utils
    budget_tracker = CreditBudget()
    budget_tracker.set_budget(budget)
    cache = ShodanCache()
    
    try:
        api = shodan.Shodan(api_key)
    except Exception as e:
        log.error(f"Failed to init Shodan API: {e}")
        return

    # 1. Gather IPs
    log.info(f"Resolving IPs for {len(domains)} domains...")
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
            
    log.info(f"Found {len(unique_ips)} unique IPs to scan.")

    # 2. Query Shodan (Sequential to respect budget safely)
    # Using concurrent futures with strict shared budget state is tricky; 
    # simple loop is safer for budget enforcement and avoids race conditions.
    
    shodan_results = {}
    count = 0
    total = len(unique_ips)
    
    for ip in unique_ips:
        count += 1
        if count % 5 == 0:
            print(f"[*] Progress: {count}/{total}", end='\r')

        cache_key = f"host:{ip}"
        
        # Check Cache
        cached_data = cache.get(cache_key)
        if cached_data:
            shodan_results[ip] = cached_data
            continue
            
        # Check Budget
        if not budget_tracker.check_can_spend(1):
            log.warning(f"Budget exhausted at {count}/{total} IPs. Skipping remaining.")
            break
            
        # Query API
        try:
            budget_tracker.spend(1)
            # minify=True reduces credit cost? No, just bandwidth. 
            # API Cost: 1 query credit per host lookup? No, standard host lookup is 1 scan credit (or free? check docs).
            # Actually host lookups deduct from scan credits, not query credits usually.
            # But we must treat them as "credits" generally.
            host_info = api.host(ip, minify=True)
            
            # Parse valuable fields
            s_data = {
                "ip": ip,
                "ports": ";".join([str(p) for p in host_info.get("ports", [])]),
                "tags": ";".join(host_info.get("tags", [])),
                "os": host_info.get("os", "") or "",
                "hostnames": ";".join(host_info.get("hostnames", [])),
                "vulns": ";".join(host_info.get("vulns", []))
            }
            
            shodan_results[ip] = s_data
            cache.set(cache_key, s_data)
            time.sleep(1) # Rate limit
            
        except shodan.APIError as e:
            # e.g. "No information available for that IP." -> Cache this as empty to avoid re-asking
            if "No information available" in str(e):
                empty_data = {"ip": ip, "ports": "", "vulns": "", "tags": "", "os": "", "hostnames": ""}
                shodan_results[ip] = empty_data
                cache.set(cache_key, empty_data)
            else:
                log.error(f"  [!] API Error for {ip}: {e}")
        except RuntimeError:
            break
        except Exception as e:
            log.error(f"  [!] Error scanning {ip}: {e}")

    print("\n[*] Shodan scan complete.")

    # 3. Map back to results
    results = []
    
    # Using ip_map to distribute results
    for ip, rows in ip_map.items():
        s_data = shodan_results.get(ip)
        
        for r in rows:
            enriched = r.copy()
            if s_data:
                enriched["shodan_ip"] = ip
                enriched.update(s_data)
            else:
                # If we ran out of budget or failed, we leave fields empty
                enriched["shodan_ip"] = ip
                enriched["ports"] = ""
                enriched["vulns"] = ""
                enriched["tags"] = ""
                enriched["os"] = ""
                enriched["hostnames"] = ""
            results.append(enriched)
    
    # 4. Write Output
    if not results:
        log.info("No results found.")
        cache.close()
        return

    # Collect all unique keys
    all_keys = set()
    for r in results:
        all_keys.update(r.keys())
    headers = sorted(list(all_keys))
    
    # Prioritize columns
    priority = ['domain', 'ip', 'shodan_ip', 'ports', 'vulns', 'tags']
    for p in reversed(priority):
        if p in headers:
            headers.insert(0, headers.pop(headers.index(p)))

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(results)
        
    log.info(f"Wrote {len(results)} rows to {output_file}")
    cache.close()


def main():
    load_dotenv()
    API_KEY = os.getenv("SHODAN_API_KEY")
    if not API_KEY:
        log.error("Error: SHODAN_API_KEY not found in .env")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/dea_domains_probed.csv")
    parser.add_argument("--output", default="data/shodan_intelligence.csv")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--budget", type=int, default=20, help="Max credits to spend")
    args = parser.parse_args()

    # Read Input
    domains = []
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                domains.append(row)
    except FileNotFoundError:
        log.error("Input file not found.")
        sys.exit(1)

    if args.limit > 0:
        domains = domains[:args.limit]

    process_shodan(API_KEY, domains, args.output, args.budget)

if __name__ == "__main__":
    main()
