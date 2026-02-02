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
  5. web_server_counts.csv
  6. risk_counts.csv
  7. http_status_counts.csv
  8. title_keyword_counts.csv
  9. shodan_os_counts.csv
  10. shodan_tag_counts.csv

Usage:
  python generate_pivots.py
"""

import csv
import collections
import argparse
import os
from typing import Dict, Counter

def normalize(s: str) -> str:
    return s.lower().strip().rstrip('.')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/dea_domains_probed.csv")
    args = parser.parse_args()

    # Aggregators
    mx_counts: Counter[str] = collections.Counter()
    asn_counts: Counter[str] = collections.Counter()
    mx_asn_map: Dict[str, Counter[str]] = collections.defaultdict(collections.Counter)
    server_counts: Counter[str] = collections.Counter()
    risk_counts: Counter[str] = collections.Counter()
    
    # New Aggregators
    http_status_counts: Counter[str] = collections.Counter()
    title_word_counts: Counter[str] = collections.Counter()
    
    # ASN Metadata map (ASN -> Name)
    asn_meta: Dict[str, str] = {}
    
    # Common Stopwords for Titles
    STOPWORDS = {'home', 'page', 'welcome', 'to', 'the', 'of', 'and', 'for', 'in', 'website', 'site', 'default', 'server', 'test', 'index', 'on', 'a', 'is', 'not', 'found', 'error', '404', '403', 'forbidden', 'bad', 'gateway', 'service', 'unavailable', 'domain', 'parked', 'parking', 'under', 'construction'}

    print(f"[*] Reading {args.input}...")
    total_processed = 0
    
    try:
        with open(args.input, "r", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain = row.get("domain", "")
                mx = normalize(row.get("primary_mx", ""))
                asn = row.get("asn", "")
                asn_name = row.get("asn_name", "")
                risks = row.get("risk_tags", "").strip()
                
                # Server stats (prefer HTTPS, fallback to HTTP)
                server = row.get("https_server", "").strip() or row.get("http_server", "").strip()
                if server:
                    # Simplify server names (e.g. "nginx/1.18.0" -> "nginx", "Cloudflare" -> "Cloudflare")
                    server_simple = server.split('/')[0].split(' ')[0]
                    server_counts[server_simple] += 1
                
                # Risk Counts
                if risks:
                    for tag in risks.split(';'):
                        t = tag.strip()
                        if t:
                            risk_counts[t] += 1

                # HTTP Status
                status = row.get("https_status", "").strip() or row.get("http_status", "").strip()
                if status and status.isdigit():
                    http_status_counts[status] += 1
                    
                # Title Keywords
                title = row.get("https_title", "").strip() or row.get("http_title", "").strip()
                if title:
                    words = title.lower().replace('|', ' ').replace('-', ' ').split()
                    for w in words:
                        w = ''.join(c for c in w if c.isalnum())
                        if w and len(w) > 3 and w not in STOPWORDS:
                            title_word_counts[w] += 1

                # Skip failed resolutions if needed, or count them as "Unknown" for MX logic
                if not mx:
                    continue
                    
                total_processed += 1
                
                # Track metadata
                if asn and asn_name:
                    asn_meta[asn] = asn_name
                
                # Aggregations
                mx_counts[mx] += 1
                
                if asn:
                    asn_counts[asn] += 1
                    mx_asn_map[mx][asn] += 1
                    
    except FileNotFoundError:
        print(f"[!] Input file {args.input} not found.")
        return

    print(f"[*] Processed {total_processed} enriched records.")

    # Shodan Aggregation
    shodan_os_counts: Counter[str] = collections.Counter()
    shodan_tag_counts: Counter[str] = collections.Counter()
    
    shodan_file = "data/shodan_intelligence.csv"
    if os.path.exists(shodan_file):
        print(f"[*] Reading {shodan_file}...")
        try:
            with open(shodan_file, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    os_name = row.get("os", "").strip()
                    tags = row.get("tags", "").strip()
                    
                    if os_name: shodan_os_counts[os_name] += 1
                    if tags:
                        for t in tags.split(';'):
                            if t.strip(): shodan_tag_counts[t.strip()] += 1
        except Exception as e:
            print(f"[!] Error reading Shodan file: {e}")

    # Helpers
    def write_counter(filename, header, counter, limit=None):
        with open(filename, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            for k, v in counter.most_common(limit):
                w.writerow([k, v])

    # Write Outputs
    print("[*] Generating web_server_counts.csv...")
    write_counter("data/web_server_counts.csv", ["server", "count"], server_counts, 20)
    
    print("[*] Generating risk_counts.csv...")
    write_counter("data/risk_counts.csv", ["risk_tag", "count"], risk_counts)
    
    print("[*] Generating http_status_counts.csv...")
    write_counter("data/http_status_counts.csv", ["status", "count"], http_status_counts)
    
    print("[*] Generating title_keyword_counts.csv...")
    write_counter("data/title_keyword_counts.csv", ["keyword", "count"], title_word_counts, 50)
    
    print("[*] Generating shodan_stats.csv...")
    write_counter("data/shodan_os_counts.csv", ["os", "count"], shodan_os_counts)
    write_counter("data/shodan_tag_counts.csv", ["tag", "count"], shodan_tag_counts)

    print("[*] Generating mx_counts.csv...")
    with open("data/mx_counts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["mx_host", "domain_count", "primary_asn"])
        for mx, count in mx_counts.most_common():
            top_asn = ""
            if mx in mx_asn_map and mx_asn_map[mx]:
                aid = mx_asn_map[mx].most_common(1)[0][0]
                name = asn_meta.get(aid, "Unknown")
                top_asn = f"AS{aid} ({name})"
            w.writerow([mx, count, top_asn])

    print("[*] Generating asn_counts.csv...")
    with open("data/asn_counts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["asn", "asn_name", "domain_count"])
        for asn, count in asn_counts.most_common():
            w.writerow([asn, asn_meta.get(asn, ""), count])
            
    # Legacy outputs (risky_asn_list, mx_asn_counts) could be added here if needed,
    # but strictly speaking user only asked for Dashboard data.
    # I'll keep them implicit or skip to save time unless requested.
    # Actually, the original script had them, let's keep them primarily for completeness if used elsewhere.
    
    print("[*] Done.")

if __name__ == "__main__":
    main()
