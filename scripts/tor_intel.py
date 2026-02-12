#!/usr/bin/env python3
"""
tor_intel.py

Fetches active Tor Exit Node IPs and Tor-associated ASNs.
Enriches IPs with ASN info and ASNs with Name/Country.

Sources:
- Tor Project (IPs): https://check.torproject.org/torbulkexitlist
- NullifiedCode (ASNs): Malicious/Tor/ASN.txt

Enrichment:
- Team Cymru DNS 

Usage:
  python tor_intel.py
"""

import argparse
import csv
import logging
import os
import re
import requests
from concurrent.futures import ThreadPoolExecutor
from typing import Set, Dict, List, Optional
from tqdm import tqdm
from shared.cymru_resolver import CymruResolver

# Configure Logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# Constants
TOR_EXIT_URL = "https://www.dan.me.uk/torlist/?exit" # Warning: 30min rate limit
# Fallback if rate limited: https://check.torproject.org/torbulkexitlist
TOR_ASN_URL = "https://raw.githubusercontent.com/NullifiedCode/ASN-Lists/main/Malicious/Tor/ASN.txt"

# Regex
ASN_REGEX = re.compile(r'(?:AS|as)?(\d+)')

class TorIntel:
    def __init__(self, output_dir: str = "data", workers: int = 10, limit: int = 0):
        self.output_dir = output_dir
        self.workers = workers
        self.limit = limit
        self.ip_set: Set[str] = set()
        self.asn_set: Set[str] = set()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "DomainIntel-Tor/1.0"})
        
        # Use shared Cymru resolver
        self.cymru = CymruResolver()

    def fetch_exits(self):
        logger.info(f"Fetching Tor Exits from {TOR_EXIT_URL}")
        try:
            resp = self.session.get(TOR_EXIT_URL, timeout=10)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.ip_set.add(line)
                logger.info(f"Loaded {len(self.ip_set)} IPs")
        except Exception as e:
            logger.error(f"Error fetching exits: {e}")

    def fetch_asns(self):
        logger.info(f"Fetching Tor ASNs from {TOR_ASN_URL}")
        try:
            resp = self.session.get(TOR_ASN_URL, timeout=10)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                for line in lines:
                    match = ASN_REGEX.search(line)
                    if match:
                        self.asn_set.add(match.group(1))
                logger.info(f"Loaded {len(self.asn_set)} ASNs")
        except Exception as e:
            logger.error(f"Error fetching ASNs: {e}")

    def enrich_ip(self, ip: str) -> Dict:
        """Resolves IP to ASN using shared Cymru resolver."""
        cymru_data = self.cymru.enrich_ip(ip)
        return {
            "IP": ip,
            "ASN": cymru_data.get("asn", ""),
            "BGP_Prefix": cymru_data.get("prefix", ""),
            "Country": cymru_data.get("country", ""),
            "Registry": ""
        }

    def enrich_asn(self, asn: str) -> Dict:
        """Resolves ASN to Name using shared Cymru resolver."""
        cymru_data = self.cymru.enrich_asn(asn)
        return {
            "ASN": cymru_data["asn"],
            "Name": cymru_data["name"],
            "Country": cymru_data["country"]
        }

    def run(self):
        # 1. Fetch
        self.fetch_exits()
        self.fetch_asns()
        
        # 2. Process
        os.makedirs(self.output_dir, exist_ok=True)

        # IPs
        ips_list = list(self.ip_set)
        if self.limit > 0: ips_list = ips_list[:self.limit]
        
        logger.info(f"Enriching {len(ips_list)} IPs...")
        enriched_ips = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            enriched_ips = list(tqdm(executor.map(self.enrich_ip, ips_list), total=len(ips_list), unit="ip"))
        
        with open(os.path.join(self.output_dir, "tor_nodes.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["IP", "ASN", "BGP_Prefix", "Country", "Registry"])
            writer.writeheader()
            writer.writerows(enriched_ips)

        # ASNs
        asns_list = list(self.asn_set)
        if self.limit > 0: asns_list = asns_list[:self.limit]

        logger.info(f"Enriching {len(asns_list)} ASNs...")
        enriched_asns = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            enriched_asns = list(tqdm(executor.map(self.enrich_asn, asns_list), total=len(asns_list), unit="asn"))
            
        with open(os.path.join(self.output_dir, "tor_asns.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ASN", "Name", "Country"])
            writer.writeheader()
            writer.writerows(enriched_asns)
            
        logger.info("Done.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()
    
    intel = TorIntel(workers=args.workers, limit=args.limit)
    intel.run()

if __name__ == "__main__":
    main()
