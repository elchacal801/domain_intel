#!/usr/bin/env python3
"""
export_stix.py

Converts enriched CSV data into STIX 2.1 JSON bundle.
Now supports:
- Enriched Domains (dea_domains_enriched.csv)
- Suspicious ASNs (suspicious_asns.csv)
- VPN/VPS ASNs (vpn_asns.csv)
- Tor ASNs (tor_asns.csv)
- Tor Exit Nodes (tor_nodes.csv)
"""

import argparse
import csv
import json
import uuid
import datetime
import os
import sys

# Constants for STIX
IDENTITY_UUID = uuid.uuid5(uuid.NAMESPACE_DNS, "domain_intel_github_action")
IDENTITY_ID = f"identity--{IDENTITY_UUID}"
TLP_CLEAR_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9" # Standard STIX TLP:CLEAR UUID

def get_timestamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def write_indicator(out, value, indicator_type, labels, name, description="", confidence=50):
    """Helper to write a single STIX indicator to the open file handle."""
    
    # Determine Pattern
    if indicator_type == "domain-name":
        pattern = f"[domain-name:value = '{value}']"
    elif indicator_type == "autonomous-system":
        clean_asn = value.upper().replace("AS", "")
        if not clean_asn.isdigit():
            return # Skip invalid
        pattern = f"[autonomous-system:number = {clean_asn}]"
    elif indicator_type == "ipv4-addr":
        pattern = f"[ipv4-addr:value = '{value}']"
    else:
        return

    # ID generation
    ind_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, pattern)}"
    
    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": ind_id,
        "created": get_timestamp(),
        "modified": get_timestamp(),
        "name": name,
        "description": description,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": get_timestamp(),
        "labels": labels,
        "indicator_types": ["malicious-activity" if "malicious" in str(labels) else "anomalous-activity"],
        "confidence": confidence,
        "created_by_ref": IDENTITY_ID,
        "object_marking_refs": [TLP_CLEAR_ID],
        "external_references": [
            {
                "source_name": "Domain Intel Repo",
                "description": "Automated threat intelligence pipeline",
                "url": "https://github.com/elchacal801/domain_intel"
            }
        ]
    }
    
    out.write(',\n')
    json.dump(obj, out, indent=4)

def process_file(out, filepath, kind, base_labels, confidence=50):
    """Generic CSV processor."""
    if not os.path.exists(filepath):
        print(f"[!] Skipping {filepath} (Not Found)")
        return

    print(f"[*] Processing {kind} from {filepath}...")
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                if kind == "domain":
                    val = row.get("domain")
                    if val:
                        labels = base_labels + ["suspicious-domain"]
                        write_indicator(out, val, "domain-name", labels, f"Suspicious Domain: {val}",confidence=confidence)
                        count += 1

                elif kind == "asn":
                    val = row.get("ASN", row.get("asn"))
                    name = row.get("Name", row.get("asn_name", "Unknown"))
                    if val:
                        labels = base_labels
                        desc = f"Suspicious ASN: {val} ({name})"
                        write_indicator(out, val, "autonomous-system", labels, desc, desc, confidence=confidence)
                        count += 1
                
                elif kind == "ip":
                    val = row.get("IP", row.get("ip"))
                    if val:
                        labels = base_labels
                        desc = f"Suspicious IP: {val} (Tor Exit)"
                        write_indicator(out, val, "ipv4-addr", labels, desc, desc, confidence=confidence)
                        count += 1
                        
            print(f"    - Added {count} indicators.")
    except Exception as e:
        print(f"[!] Error processing {filepath}: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/dea_domains_enriched.csv", help="Main Domain Input")
    parser.add_argument("--output", default="data/domain_intel_bundle.json")
    # Optional overrides for other files
    parser.add_argument("--suspicious-asns", default="data/suspicious_asns.csv")
    parser.add_argument("--vpn-asns", default="data/vpn_asns.csv")
    parser.add_argument("--tor-nodes", default="data/tor_nodes.csv")
    parser.add_argument("--tor-asns", default="data/tor_asns.csv")
    
    args = parser.parse_args()
    
    print(f"[*] Starting STIX Export to {args.output}...")

    with open(args.output, "w", encoding="utf-8") as out:
        # Bundle Header
        bundle_id = f"bundle--{uuid.uuid4()}"
        out.write('{\n')
        out.write(f'  "type": "bundle",\n')
        out.write(f'  "id": "{bundle_id}",\n')
        out.write('  "objects": [\n')

        # Identity
        identity_obj = {
            "type": "identity",
            "spec_version": "2.1",
            "id": IDENTITY_ID,
            "created": get_timestamp(),
            "modified": get_timestamp(),
            "name": "Domain Intel Bot",
            "identity_class": "system",
            "description": "Automated Domain Intelligence GitHub Action/Bot",
            "object_marking_refs": [TLP_CLEAR_ID]
        }
        json.dump(identity_obj, out, indent=4)
        
        # TLP Marking Definition
        out.write(',\n')
        tlp_obj = {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": TLP_CLEAR_ID,
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp",
            "name": "TLP:CLEAR",
            "definition": {
                "tlp": "clear"
            }
        }
        json.dump(tlp_obj, out, indent=4)
        
        # Process Domains (Main Input)
        process_file(out, args.input, "domain", ["malicious-activity", "anomalous-activity"], confidence=60)
        
        # Process Suspicious ASNs
        process_file(out, args.suspicious_asns, "asn", ["malicious-activity", "hosting-provider"], confidence=70)
        
        # Process VPN ASNs
        process_file(out, args.vpn_asns, "asn", ["anonymization", "vpn-provider"], confidence=50)
        
        # Process Tor ASNs
        process_file(out, args.tor_asns, "asn", ["anonymization", "tor-network"], confidence=90)
        
        # Process Tor Nodes
        process_file(out, args.tor_nodes, "ip", ["anonymization", "tor-exit"], confidence=95)

        # Close Bundle
        out.write('\n  ]\n')
        out.write('}\n')

    print("[*] STIX Export Complete.")

if __name__ == "__main__":
    main()
