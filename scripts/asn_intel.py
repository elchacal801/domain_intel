#!/usr/bin/env python3
"""
asn_intel.py

Fetches suspicious ASN lists from community sources, enriches them with Team Cymru DNS metadata,
flags high-value targets, and exports to CSV.

Sources:
- NullifiedCode ASN List
- Mthcht Awesome Lists (ASNs)

Enrichment:
- Team Cymru DNS (AS{asn}.asn.cymru.com)

Usage:
  python asn_intel.py --output data/suspicious_asns.csv
"""

import argparse
import csv
import json
import logging
import os
import re
import time
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Dict, List, Optional
from tqdm import tqdm
from shared.cymru_resolver import CymruResolver

# Configure Logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# Constants
NULLIFIED_LIST_URL = "https://raw.githubusercontent.com/NullifiedCode/ASN-Lists/master/all.txt"
LORENZO_LIST_URL = "https://raw.githubusercontent.com/LorenzoSapora/bad-asn-list/master/raw.txt"
BRIANHAMA_LIST_URL = "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv"
NULLIFIED_MALICIOUS_URL = "https://raw.githubusercontent.com/NullifiedCode/ASN-Lists/main/Malicious/ASN.txt"

MTHCHT_REPO_API = "https://api.github.com/repos/mthcht/awesome-lists/contents/Lists/ASNs"
# Fallback raw base in case we just want to iterate known files or if API fails
MTHCHT_RAW_BASE = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/ASNs/"

# High Value Targets (HVT)
HVT_MAP = {
    "39287": "Njalla",
    "51852": "PrivateAlps",
    "50613": "OrangeWebsite",
    "200651": "FlokiNET",
    "45839": "Shinjiru",
    "149457": "BlueAngelHost"
}

# Regex to extract numeric ASN (kept for source-specific parsing; CymruResolver.clean_asn also available)
ASN_REGEX = re.compile(r'(?:AS|as)?(\d+)')

class ASNIntel:
    def __init__(self, output_file: str, workers: int = 5, limit: int = 0):
        self.output_file = output_file
        self.workers = workers
        self.limit = limit
        self.asn_set: Set[str] = set()
        self.enriched_data: List[Dict] = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "DomainIntel-ASN/1.0"})
        
        # Use shared Cymru resolver
        self.cymru = CymruResolver()

    def fetch_nullified_list(self):
        """Fetches the NullifiedCode all.txt list."""
        self.fetch_simple_list(NULLIFIED_LIST_URL, "NullifiedCode All")

    def fetch_simple_list(self, url: str, source_name: str):
        """Generic fetcher for line-based ASN lists."""
        logger.info(f"Fetching {source_name} list from {url}")
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
                logger.info(f"Loaded {count} ASNs from {source_name}")
            else:
                logger.error(f"Failed to fetch {source_name} list: {resp.status_code}")
        except Exception as e:
            logger.error(f"Error fetching {source_name} list: {e}")

    def fetch_mthcht_lists(self):
        """Fetches file list from mthcht repo and then processes each file."""
        logger.info("Fetching Mthcht lists...")
        try:
            # list files via GitHub API
            resp = self.session.get(MTHCHT_REPO_API, timeout=10)
            if resp.status_code == 200:
                files = resp.json()
                txt_files = [f for f in files if f['name'].endswith('.txt') or f['name'].endswith('.csv')]
                
                logger.info(f"Found {len(txt_files)} files in Mthcht repo. Downloading content...")
                
                for f_obj in txt_files:
                    raw_url = f_obj.get('download_url')
                    if raw_url:
                        self._fetch_single_list(raw_url)
            else:
                logger.error(f"Failed to list Mthcht files: {resp.status_code}. Rate limit might be hit.")
                # Fallback functionality could be added here if needed
        except Exception as e:
            logger.error(f"Error fetching Mthcht lists: {e}")

    def _fetch_single_list(self, url: str):
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                for line in lines:
                    asn = self._clean_asn(line)
                    if asn:
                        self.asn_set.add(asn)
        except Exception:
            pass

    def _clean_asn(self, raw_text: str) -> Optional[str]:
        """Extracts numeric ASN string from text."""
        match = ASN_REGEX.search(raw_text)
        if match:
            return match.group(1)
        return None

    def enrich_asn(self, asn: str) -> Dict:
        """Queries Team Cymru via DNS for ASN details using shared resolver."""
        cymru_data = self.cymru.enrich_asn(asn)
        
        data = {
            "ASN": cymru_data["asn"],
            "Name": cymru_data["name"],
            "Country": cymru_data["country"],
            "Source_List": "Unknown",
            "Is_High_Value_Target": False,
            "Target_Type": ""
        }

        # Check HVT
        if asn in HVT_MAP:
            data["Is_High_Value_Target"] = True
            data["Target_Type"] = HVT_MAP[asn]

        return data

    def run(self):
        # 1. Fetch
        self.fetch_nullified_list()
        self.fetch_simple_list(LORENZO_LIST_URL, "LorenzoSapora")
        self.fetch_simple_list(BRIANHAMA_LIST_URL, "BrianHama")
        self.fetch_simple_list(NULLIFIED_MALICIOUS_URL, "NullifiedCode Malicious")
        self.fetch_mthcht_lists()

        asns_list = list(self.asn_set)
        total_asns = len(asns_list)
        logger.info(f"Total unique ASNs to process: {total_asns}")

        if self.limit > 0:
            logger.info(f"Limiting processing to {self.limit} ASNs")
            asns_list = asns_list[:self.limit]

        # 2. Enrich
        logger.info("Enriching ASNs with Team Cymru DNS...")
        
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            # DNS is fast, so we can probably bump workers if needed, but 5 is safe default
            full_results = list(tqdm(executor.map(self.enrich_asn, asns_list), total=len(asns_list), unit="asn"))
            self.enriched_data = full_results

        # 3. Output
        self.save_csv()

    def save_csv(self):
        # Sort: High Value (True -> False), then ASN
        self.enriched_data.sort(key=lambda x: (not x["Is_High_Value_Target"], x["ASN"]))

        headers = ["ASN", "Name", "Country", "Source_List", "Is_High_Value_Target", "Target_Type"]
        
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
    parser = argparse.ArgumentParser(description="ASN Intel: Fetch and Enrich Suspicious ASNs")
    parser.add_argument("--output", default="data/suspicious_asns.csv", help="Path to output CSV")
    parser.add_argument("--workers", type=int, default=10, help="Number of concurrent workers (default 10 for DNS)")
    parser.add_argument("--limit", type=int, default=0, help="Test limit (0=all)")
    
    args = parser.parse_args()
    
    intel = ASNIntel(output_file=args.output, workers=args.workers, limit=args.limit)
    intel.run()

if __name__ == "__main__":
    main()
