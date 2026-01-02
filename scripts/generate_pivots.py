#!/usr/bin/env python3
"""
generate_pivots.py

Derives infrastructure intelligence datasets from enriched domain data.
Input: dea_domains_enriched.csv
Outputs:
  1. mx_counts.csv      -> Top MX providers by domain count
  2. asn_counts.csv     -> Top Hosting ASNs by domain count
  3. mx_asn_counts.csv  -> Correlation between MX provider and ASN
  4. risky_asn_list.csv -> List of ASNs with high concentration of DEA domains

Usage:
  python generate_pivots.py
"""

import csv
import collections
import argparse
from typing import Dict, Counter

def normalize(s: str) -> str:
    return s.lower().strip().rstrip('.')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/dea_domains_enriched.csv")
    args = parser.parse_args()

    # Aggregators
    mx_counts: Counter[str] = collections.Counter()
    asn_counts: Counter[str] = collections.Counter()
    mx_asn_map: Dict[str, Counter[str]] = collections.defaultdict(collections.Counter)
    
    # ASN Metadata map (ASN -> Name)
    asn_meta: Dict[str, str] = {}
    
    # Read Input
    total_processed = 0
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain = row.get("domain", "")
                mx = normalize(row.get("primary_mx", ""))
                asn = row.get("asn", "")
                asn_name = row.get("asn_name", "")
                
                # Skip failed resolutions if needed, or count them as "Unknown"
                if not mx:
                    continue
                    
                total_processed += 1
                
                # Track metadata
                if asn and asn_name:
                    asn_meta[asn] = asn_name
                
                # Aggregations
                mx_counts[mx] += 1
                
                if asn:
                    asn_key = asn
                    asn_counts[asn_key] += 1
                    mx_asn_map[mx][asn_key] += 1
                    
    except FileNotFoundError:
        print(f"[!] Input file {args.input} not found. Run enrich_infrastructure.py first.")
        return

    print(f"[*] Processed {total_processed} enriched records.")

    # 1. mx_counts.csv
    print("[*] Generating mx_counts.csv...")
    with open("data/mx_counts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["mx_host", "domain_count", "primary_asn"])
        # For primary ASN, we'll pick the most common ASN seen for this MX
        for mx, count in mx_counts.most_common():
            # Find top ASN for this MX
            top_asn = ""
            if mx in mx_asn_map:
                top_asn_stats = mx_asn_map[mx].most_common(1)
                if top_asn_stats:
                    aid = top_asn_stats[0][0]
                    name = asn_meta.get(aid, "Unknown")
                    top_asn = f"AS{aid} ({name})"
            
            w.writerow([mx, count, top_asn])

    # 2. asn_counts.csv
    print("[*] Generating asn_counts.csv...")
    with open("data/asn_counts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["asn", "asn_name", "domain_count"])
        for asn, count in asn_counts.most_common():
            w.writerow([asn, asn_meta.get(asn, ""), count])

    # 3. mx_asn_counts.csv
    print("[*] Generating mx_asn_counts.csv...")
    with open("data/mx_asn_counts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["mx_host", "asn", "asn_name", "domain_count"])
        
        # Sort by MX count first
        sorted_mxs = [m for m, c in mx_counts.most_common()]
        
        for mx in sorted_mxs:
            asn_subcounts = mx_asn_map.get(mx, Counter())
            for asn, count in asn_subcounts.most_common():
                w.writerow([mx, asn, asn_meta.get(asn, ""), count])

    # 4. risky_asn_list.csv (Threshold: > 5 domains? Or just all sorted)
    # The prompt asks for "High-risk hosting ASNs". We'll include all but sorted by risk (count).
    print("[*] Generating risky_asn_list.csv...")
    with open("data/risky_asn_list.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["asn", "asn_name", "risk_score_domains"])
        for asn, count in asn_counts.most_common():
             w.writerow([asn, asn_meta.get(asn, ""), count])

    print("[*] Done.")

if __name__ == "__main__":
    main()
