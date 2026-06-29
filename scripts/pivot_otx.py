#!/usr/bin/env python3
"""
pivot_otx.py

Passive DNS Pivot utilizing AlienVault OTX API.
Resolves target domains to IPs (or takes IPs directly) and queries OTX
for other domains hosted on the same infrastructure.

Usage:
    python pivot_otx.py domain1.com 1.2.3.4 --output data/results.csv
"""

import argparse
import csv
import os

from shared.otx_client import query_otx_passive_dns, resolve_target
from shared.sanitize import sanitize_csv_value


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
                    'discovered_domain': sanitize_csv_value(d),
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
