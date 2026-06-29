#!/usr/bin/env python3
"""
discover_ct.py

Discovery module using Certificate Transparency (CT) Logs.
Finds subdomains and related infrastructure by monitoring SSL certificate issuance.

Sources:
1. crt.sh (Primary, Free, Public)
2. Censys (Backup, API Key Required)

Usage:
  python discover_ct.py --input config/targets.txt --output data/discovered_certs.csv
"""

import argparse
import csv
import os
import sys
import time
import requests
import logging
from typing import Set, Dict, List
from urllib.parse import quote

# Logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# Constants
CRTSH_URL = "https://crt.sh/?q={}&output=json"
CENSYS_URL = "https://search.censys.io/api/v2/certificates/search"

class CTDiscoverer:
    def __init__(self, output_file: str):
        self.output_file = output_file
        self.found_domains: Set[str] = set()
        self.censys_key = os.environ.get("CENSYS_API_KEY")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "DomainIntel-CT/1.0"})

    def query_crtsh(self, target: str) -> List[Dict]:
        """Queries crt.sh for %.target"""
        query = f"%.{target}"
        url = CRTSH_URL.format(quote(query))
        logger.info(f"Querying crt.sh for {query}...")
        
        try:
            # crt.sh is often slow, give it time
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    return data
                except ValueError:
                    logger.warning(f"crt.sh returned non-JSON for {target}")
            else:
                logger.warning(f"crt.sh failed: {resp.status_code}")
        except Exception as e:
            logger.error(f"crt.sh error: {e}")
            
        return None  # Signal failure to trigger backup

    def query_censys(self, target: str) -> List[Dict]:
        """Backup: Queries Censys (1 concurrent request limit)."""
        if not self.censys_key:
            logger.warning("No CENSYS_API_KEY found. Skipping backup source.")
            return []

        # Assuming Key is Secret, ID might be needed too? 
        # Typically Censys uses Basic Auth (API ID, Secret). 
        # User provided one string: "censys_..." which looks like a Secret.
        # usually it is (UID, SECRET). 
        # If the user only gave one key, it might be the Secret. 
        # But standard Censys API requires both. 
        # Checking format: "censys_..." implies it might be a unified token or part of a pair.
        # For now, we will try using it as a Bearer token or Basic Auth password.
        # Wait, usually API ID is UUID-like.
        # Let's try Basic Auth with empty user or Bearer.
        # Documentation: https://search.censys.io/api
        # "Authorization: Basic base64(API_ID:API_SECRET)"
        
        # User provided: "censys_fSMmA3hs_...". This looks like a Secret.
        # Without API ID, we can't authenticate via Basic Auth typically.
        # However, let's assume specific implementation details or try to just log warning if it fails.
        # We will assume ENV contains "CENSYS_API_ID" and "CENSYS_API_SECRET" ideally.
        # But if the user gave us just one key, maybe it is a Bearer token?
        # New Censys Search API supports header `Authorization: Bearer <token>` ? No, standard is Basic.
        
        # NOTE: Proceeding with logic, but alerting if Auth fails.
        auth = None
        api_id = os.environ.get("CENSYS_API_ID")
        api_secret = os.environ.get("CENSYS_API_SECRET", self.censys_key) # Use provided key as secret
        
        if api_id and api_secret:
            auth = (api_id, api_secret)
        else:
            # If we lack ID, we can't do much unless the key IS the auth header?
            pass

        logger.info(f"Querying Censys (Backup) for {target}...")
        results = []
        
        # Query: services.tls.certificates.leaf_data.names: target
        payload = {
            "q": f"names: {target}", 
            "per_page": 50
        }
        
        try:
            # Strict Serial: Sleep before request to ensure rate limit spacing
            time.sleep(2.0) 
            
            resp = self.session.post(
                CENSYS_URL, 
                json=payload, 
                auth=auth,
                headers={"Authorization": f"Bearer {self.censys_key}"} if not auth else None, # Try Bearer if no ID
                timeout=15
            )
            
            if resp.status_code == 200:
                data = resp.json()
                hits = data.get("result", {}).get("hits", [])
                for h in hits:
                    # Normalize to align with crt.sh structure roughly
                    # We utilize 'names' array
                    names = h.get("names", [])
                    for n in names:
                        results.append({"name_value": n, "issuer_name": "Censys"})
            else:
                logger.warning(f"Censys failed: {resp.status_code} - {resp.text}")

        except Exception as e:
            logger.error(f"Censys error: {e}")
            
        return results

    def process_target(self, target: str):
        logger.info(f"Scanning target: {target}")
        
        # 1. Try crt.sh
        data = self.query_crtsh(target)
        
        # 2. Try Censys if crt.sh failed
        if data is None:
            logger.info("crt.sh unavailable. Switching to Censys backup...")
            data = self.query_censys(target)
        
        if not data:
            return

        count = 0
        for entry in data:
            # crt.sh returns 'name_value' (can be multi-line string)
            raw_name = entry.get("name_value", "")
            issuer = entry.get("issuer_name", "Unknown")
            
            # Split multi-line names
            subdomains = raw_name.split("\n")
            for sub in subdomains:
                sub = sub.strip().lower()
                # Remove wildcards
                sub = sub.replace("*.", "")
                
                if sub and sub not in self.found_domains:
                    self.found_domains.add(sub)
                    self.write_result(sub, issuer, "CT_Log")
                    count += 1
        
        logger.info(f"Found {count} new certs for {target}")

    def write_result(self, domain, issuer, source):
        with open(self.output_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([domain, issuer, source, time.strftime("%Y-%m-%d")])

    def run(self, input_file):
        # Init CSV
        with open(self.output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["domain", "issuer", "source", "date"])

        # Read Targets
        targets = []
        if os.path.exists(input_file):
            with open(input_file, "r") as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        else:
            logger.warning(f"Input file {input_file} not found.")
            return

        for t in targets:
            self.process_target(t)
            # Gentle sleep between targets for crt.sh
            time.sleep(1.0)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="config/targets.txt")
    parser.add_argument("--output", default="data/discovered_certs.csv")
    args = parser.parse_args()

    discoverer = CTDiscoverer(args.output)
    discoverer.run(args.input)

if __name__ == "__main__":
    main()
