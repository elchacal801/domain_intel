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

    # 2. Query Shodan (Batch if possible, but standard API is usually single IP)
    # Handling rate limits: Free API is 1 req/sec usually.
    
    results = []
    
    count = 0
    for ip in unique_ips:
        count += 1
        shodan_data = {
            "ip": ip,
            "ports": "",
            "vulns": "",
            "tags": "",
            "os": "",
            "hostnames": ""
        }
        
        try:
            print(f"[*] Scanning {ip} ({count}/{len(unique_ips)})...", end='\r')
            host = api.host(ip)
            
            shodan_data["ports"] = ";".join([str(p) for p in host.get("ports", [])])
            shodan_data["tags"] = ";".join(host.get("tags", []))
            shodan_data["os"] = host.get("os", "")
            shodan_data["hostnames"] = ";".join(host.get("hostnames", []))
            shodan_data["vulns"] = ";".join(host.get("vulns", [])) # List of CVEs
            
        except shodan.APIError as e:
            # "No information available for that IP" is common
            pass
        except Exception as e:
            log(f"Error scanning {ip}: {e}")
            
        # Map back to domains
        for row in ip_map[ip]:
            enriched_row = row.copy()
            enriched_row["shodan_ip"] = ip
            enriched_row.update(shodan_data)
            results.append(enriched_row)
            
    print("") # Newline
    
    # 3. Write Output
    if not results:
        log("No results found.")
        return

    headers = list(results[0].keys())
    # Ensure consistent headers if some rows missing keys
    
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
