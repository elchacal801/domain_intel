#!/usr/bin/env python3
"""
export_stix.py

Converts enriched CSV data into STIX 2.1 JSON bundle.
Objects:
- Indicator (Domain)
- Infrastructure (Hosting ASN/IP) - optional, or just Observed Data.
- Relationship (resolves-to)

Usage:
  python export_stix.py --input data/dea_domains_probed.csv --output data/domain_intel.json
"""

import argparse
import csv
import json
import uuid
import datetime
from typing import List, Dict

try:
    from stix2 import Bundle, Indicator, Infrastructure, Relationship, Identity, ObservedData
    from stix2 import IPv4Address, DomainName, AutonomousSystem
except ImportError:
    print("stix2 library not found. Install it via pip install stix2")
    exit(1)

IDENTITY_ID = "identity--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, "domain_intel_github_action"))

def create_identity():
    return Identity(
        id=IDENTITY_ID,
        name="Domain Intel Bot",
        identity_class="system",
        description="Automated Domain Intelligence GitHub Action"
    )

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/dea_domains_enriched.csv", help="Last enriched CSV")
    ap.add_argument("--output", default="docs/data/domain_intel_bundle.json")
    args = ap.parse_args()
    
    objects = []
    
    # Create source identity
    ident = create_identity()
    objects.append(ident)
    
    print(f"[*] Reading {args.input}...")
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    except FileNotFoundError:
        print("[!] Input file not found.")
        return

    print(f"[*] Converting {len(rows)} records to STIX...")
    
    for row in rows:
        domain = row.get("domain")
        if not domain: continue
        
        # Indicator: The Domain
        # We assume these are 'anomalous' or 'suspicious' logic based on the list they are in.
        inda = Indicator(
            name=f"Suspicious Domain: {domain}",
            pattern=f"[domain-name:value = '{domain}']",
            pattern_type="stix",
            valid_from=datetime.datetime.now(datetime.timezone.utc),
            labels=["malicious-activity", "anomalous-activity"],
            created_by_ref=IDENTITY_ID
        )
        objects.append(inda)
        
        # Infrastructure: IP (if resolved)
        mx_ip = row.get("mx_ip")
        if mx_ip:
            # We observe this IP
            # For simplicity, let's just create an Infrastructure object for the server
            # or just rely on the fact that an indicator points to it.
            # STIX best practice for simple feeds: Indicator -> Observed Data.
            # But let's make it graph-y.
            pass

    # Create Bundle
    bundle = Bundle(objects=objects, allow_custom=True)
    
    # Serialize
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(bundle.serialize(pretty=True))
        
    print(f"[*] Wrote bundle to {args.output} ({len(objects)} objects)")

if __name__ == "__main__":
    main()
