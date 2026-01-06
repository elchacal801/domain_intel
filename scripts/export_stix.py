#!/usr/bin/env python3
"""
export_stix.py

Converts enriched CSV data into STIX 2.1 JSON bundle.
Optimized for performance: Streams output JSON to handle large datasets (200k+).
"""

import argparse
import csv
import json
import uuid
import datetime
import sys

# Constants for STIX
IDENTITY_UUID = uuid.uuid5(uuid.NAMESPACE_DNS, "domain_intel_github_action")
IDENTITY_ID = f"identity--{IDENTITY_UUID}"

def get_timestamp():
    # STIX 2.1 requires UTC timestamps
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/dea_domains_enriched.csv", help="Last enriched CSV")
    ap.add_argument("--output", default="docs/data/domain_intel_bundle.json")
    args = ap.parse_args()
    
    print(f"[*] Reading {args.input}...")
    try:
        # Check file line count first for progress (optional, but helpful)
        total_lines = 0
        with open(args.input, "r", encoding="utf-8") as f:
            total_lines = sum(1 for _ in f) - 1 # minus header
    except FileNotFoundError:
        print("[!] Input file not found.")
        return

    print(f"[*] Streaming STIX conversion for ~{total_lines} records to {args.output}...")

    # Open output file
    with open(args.output, "w", encoding="utf-8") as out:
        # Write Bundle Header
        bundle_id = f"bundle--{uuid.uuid4()}"
        out.write('{\n')
        out.write(f'  "type": "bundle",\n')
        out.write(f'  "id": "{bundle_id}",\n')
        out.write('  "objects": [\n')

        # Write Identity Object
        # We write it manually to control comma placement easily
        identity_obj = {
            "type": "identity",
            "spec_version": "2.1",
            "id": IDENTITY_ID,
            "created": get_timestamp(),
            "modified": get_timestamp(),
            "name": "Domain Intel Bot",
            "identity_class": "system",
            "description": "Automated Domain Intelligence GitHub Action/Bot"
        }
        
        json.dump(identity_obj, out, indent=4)
        
        # Track if we need a comma
        first_item = False 
        
        # Process CSV
        with open(args.input, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            
            count = 0
            for row in reader:
                domain = row.get("domain")
                if not domain: continue

                # Always add comma before next item (since Identity was first)
                out.write(',\n')
                
                # Create Indicator Object
                # Deterministic ID based on domain to avoid dups if run multiple times (optional, but good practice)
                # Using random UUID for now to be safe/simple, or v5 with namespace?
                # Let's use v5 for stability between runs if needed, but random is faster/easier logic.
                # Actually, STIX requires ID uniqueness. v5 is better for deduplication.
                ind_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, domain)}"
                
                # Check for other attributes to enrich labels
                labels = ["malicious-activity", "anomalous-activity"]
                
                indicator_obj = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created": get_timestamp(),
                    "modified": get_timestamp(),
                    "name": f"Suspicious Domain: {domain}",
                    "pattern": f"[domain-name:value = '{domain}']",
                    "pattern_type": "stix",
                    "valid_from": get_timestamp(),
                    "labels": labels,
                    "created_by_ref": IDENTITY_ID
                }
                
                json.dump(indicator_obj, out, indent=4)
                count += 1
                
                if count % 10000 == 0:
                    print(f"[*] Processed {count}...", end='\r')

        # Close JSON structure
        out.write('\n  ]\n')
        out.write('}\n')

    print(f"\n[*] Done. Wrote {count} indicators to {args.output}")

if __name__ == "__main__":
    main()
