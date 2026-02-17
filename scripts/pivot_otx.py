
import os
import requests
import argparse
import socket
import csv
from dotenv import load_dotenv

"""
pivot_otx.py

Passive DNS Pivot utilizing AlienVault OTX API.
Resolves target domains to IPs (or takes IPs directly) and queries OTX 
for other domains hosted on the same infrastructure.

Usage:
    python pivot_otx.py domain1.com 1.2.3.4 --output data/results.csv
"""

# Load environment variables
load_dotenv()

OTX_API_KEY = os.getenv("ALIENVAULT_OTX_API_KEY")

def resolve_target(target):
    try:
        # Check if already an IP
        socket.inet_aton(target)
        return target
    except socket.error:
        # Resolve domain
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            print(f"[!] Could not resolve {target}")
            return None

def query_otx_passive_dns(ip):
    if not OTX_API_KEY:
        print("[!] ALIENVAULT_OTX_API_KEY not found in .env")
        return []

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            passive_dns = data.get('passive_dns', [])
            return [record.get('hostname') for record in passive_dns if record.get('hostname')]
        else:
            print(f"[!] Error {response.status_code} querying OTX for {ip}")
            return []
    except Exception as e:
        print(f"[!] Exception querying OTX for {ip}: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="Pivot on IP/Domain using OTX Passive DNS")
    parser.add_argument("targets", nargs='+', help="List of domains or IPs to pivot on")
    parser.add_argument("--output", default="data/pivot_otx_results.csv", help="Output CSV file")
    args = parser.parse_args()

    all_results = []
    
    print(f"[*] Starting OTX Pivot for {len(args.targets)} targets...")

    for target in args.targets:
        ip = resolve_target(target)
        if not ip:
            continue
            
        print(f"[*] Pivoting on {target} ({ip})...")
        domains = query_otx_passive_dns(ip)
        
        if domains:
            print(f"    + Found {len(domains)} domains")
            for d in domains:
                all_results.append({
                    'pivot_selector': target,
                    'pivot_ip': ip,
                    'discovered_domain': d,
                    'source': 'AlienVault_OTX'
                })
        else:
            print("    - No domains found.")

    if all_results:
        # Write to CSV
        file_exists = os.path.exists(args.output)
        with open(args.output, 'a', newline='', encoding='utf-8') as f:
            headers = ['pivot_selector', 'pivot_ip', 'discovered_domain', 'source']
            writer = csv.DictWriter(f, fieldnames=headers)
            if not file_exists:
                writer.writeheader()
            writer.writerows(all_results)
        print(f"[*] Wrote {len(all_results)} results to {args.output}")
    else:
        print("[*] No results to write.")

if __name__ == "__main__":
    main()
