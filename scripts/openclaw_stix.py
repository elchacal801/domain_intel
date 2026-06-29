#!/usr/bin/env python3
"""
openclaw_stix.py

Generates STIX 2.1 Bundle from OpenClaw scan results.
Maps exposed instances to Infrastructure and Sighting objects.
"""

import csv
import json
import uuid
import logging
from datetime import datetime, timezone
from stix2 import Bundle, Infrastructure, Sighting, Indicator, Relationship, Identity
from stix2 import ObjectPath, EqualityComparisonExpression

# Setup Logging
logging.basicConfig(level=logging.INFO, format='[*] %(message)s')
log = logging.getLogger("openclaw_stix")

def generate_stix_bundle(input_csv: str, output_json: str):
    objects = []
    
    # 1. Identity (Us)
    identity = Identity(
        name="Domain Intel - OpenClaw Scanner",
        identity_class="system",
        description="Automated scanner for exposed AI agents."
    )
    objects.append(identity)

    # 2. Indicator (The Pattern)
    indicator = Indicator(
        name="Exposed OpenClaw Instance",
        pattern="[network-traffic:dst_port = 18789]",
        pattern_type="stix",
        valid_from=datetime.now(timezone.utc),
        description="Detects traffic to default OpenClaw gateway port."
    )
    objects.append(indicator)

    # 3. Process Findings
    try:
        with open(input_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get('ip')
                if not ip: continue
                
                # Infrastructure Object
                infra = Infrastructure(
                    name=f"OpenClaw Node - {ip}",
                    description=f"Exposed OpenClaw instance. Risk: {row.get('risk_level')}. Org: {row.get('org')}",
                    infrastructure_types=["botnet", "command-and-control"],
                    labels=["openclaw", "shadow-ai", f"risk-{row.get('risk_level', 'low').lower()}"],
                    allow_custom=True
                )
                objects.append(infra)
                
                # Sighting
                sighting = Sighting(
                    sighting_of_ref=indicator.id,
                    count=1,
                    description=f"Found {ip} exposed on port 18789",
                    allow_custom=True
                )
                objects.append(sighting)
                
                # Relationship: Sighting relates to Infrastructure
                # Actually, Sighting has 'where_sighted_refs' for Identity/Location.
                # STIX best practice: Relationship(source=infra, relationship_type='located-at', target=identity) doesn't fit here.
                # Correct used: Relationship(source=indicator, relationship_type='indicates', target=infra)
                
                rel = Relationship(
                    source_ref=indicator.id,
                    target_ref=infra.id,
                    relationship_type="indicates",
                    description="Indicator detected this infrastructure node."
                )
                objects.append(rel)
                
    except FileNotFoundError:
        log.error(f"Input file {input_csv} not found.")
        return

    # 4. Create Bundle
    bundle = Bundle(objects=objects, allow_custom=True)
    
    with open(output_json, 'w') as f:
        f.write(str(bundle))
        
    log.info(f"Wrote STIX bundle to {output_json} with {len(objects)} objects.")

if __name__ == "__main__":
    generate_stix_bundle("data/openclaw_exposed.csv", "data/openclaw_stix.json")
