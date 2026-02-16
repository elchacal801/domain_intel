#!/usr/bin/env python3
"""
vpn_intel.py

Fetches ASNs associated with VPN and VPS providers from NullifiedCode,
enriches them with Team Cymru DNS metadata, and exports to CSV.

Sources:
- NullifiedCode VPN Providers
- NullifiedCode VPS Providers

Enrichment:
- Team Cymru DNS (AS{asn}.asn.cymru.com)

Usage:
  python vpn_intel.py --output data/vpn_asns.csv
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
VPN_ASN_URL = "https://raw.githubusercontent.com/NullifiedCode/ASN-Lists/main/VPN%20Providers/ASN.txt"
VPS_ASN_URL = "https://raw.githubusercontent.com/NullifiedCode/ASN-Lists/main/VPS%20Providers/ASN.txt"

# Regex to extract numeric ASN
ASN_REGEX = re.compile(r'(?:AS|as)?(\d+)')

class VPNIntel:
    def __init__(self, output_file: str, workers: int = 10, limit: int = 0):
        self.output_file = output_file
        self.workers = workers
        self.limit = limit
        self.asn_set: Set[str] = set()
        self.enriched_data: List[Dict] = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "DomainIntel-VPN/1.0"})
        
        # Use shared Cymru resolver
        self.cymru = CymruResolver()

    def fetch_list(self, url: str, source_type: str):
        """Fetches ASN list from URL."""
        logger.info(f"Fetching {source_type} list from {url}")
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                count = 0
                for line in lines:
                    asn = self._clean_asn(line)
                    if asn:
                        self.asn_set.add(asn)
                        count += 1
                logger.info(f"Loaded {count} ASNs from {source_type}")
            else:
                logger.error(f"Failed to fetch {source_type} list: {resp.status_code}")
        except Exception as e:
            logger.error(f"Error fetching {source_type} list: {e}")

    def _clean_asn(self, raw_text: str) -> Optional[str]:
        """Extracts numeric ASN string from text."""
        match = ASN_REGEX.search(raw_text)
        if match:
            return match.group(1)
        return None

    def enrich_asn(self, asn: str) -> Dict:
        """Queries Team Cymru via DNS for ASN details using shared resolver."""
        cymru_data = self.cymru.enrich_asn(asn)
        return {
            "ASN": cymru_data["asn"],
            "Name": cymru_data["name"],
            "Country": cymru_data["country"],
            "Source": "VPN/VPS",
            "Registry": cymru_data.get("registry", ""),
            "Alloc_Date": cymru_data.get("date", "")
        }

    def run(self):
        # 1. Fetch
        self.fetch_list(VPN_ASN_URL, "VPN Providers")
        self.fetch_list(VPS_ASN_URL, "VPS Providers")

        asns_list = list(self.asn_set)
        total_asns = len(asns_list)
        logger.info(f"Total unique ASNs to process: {total_asns}")

        if self.limit > 0:
            logger.info(f"Limiting processing to {self.limit} ASNs")
            asns_list = asns_list[:self.limit]

        # 2. Enrich
        logger.info("Enriching ASNs with Team Cymru DNS...")
        
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            full_results = list(tqdm(executor.map(self.enrich_asn, asns_list), total=len(asns_list), unit="asn"))
            self.enriched_data = full_results

        # 3. Output
        self.save_csv()

    def save_csv(self):
        self.enriched_data.sort(key=lambda x: x["ASN"])
        headers = ["ASN", "Name", "Country", "Source", "Registry", "Alloc_Date"]
        
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        
        try:
            with open(self.output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                for row in self.enriched_data:
                    clean_row = {k: row.get(k, "") for k in headers}
                    writer.writerow(clean_row)
            logger.info(f"Successfully saved to {self.output_file}")
        except Exception as e:
            logger.error(f"Failed to write CSV: {e}")

def main():
    parser = argparse.ArgumentParser(description="VPN Intel: Fetch and Enrich VPN/VPS ASNs")
    parser.add_argument("--output", default="data/vpn_asns.csv", help="Path to output CSV")
    parser.add_argument("--workers", type=int, default=10, help="Number of concurrent workers (default 10)")
    parser.add_argument("--limit", type=int, default=0, help="Test limit (0=all)")
    
    args = parser.parse_args()
    
    intel = VPNIntel(output_file=args.output, workers=args.workers, limit=args.limit)
    intel.run()

if __name__ == "__main__":
    main()
