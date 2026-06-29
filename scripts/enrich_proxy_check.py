#!/usr/bin/env python3
"""
enrich_proxy_check.py

Enriches IPs with residential proxy / VPN detection via proxycheck.io API.
Free tier: 1,000 queries/day (registered), 100/day (unregistered).

Reads a CSV with an IP column, queries proxycheck.io, and appends:
  proxy_detected, proxy_type, proxy_risk, proxy_provider

Usage:
  python enrich_proxy_check.py --input data/triage_candidates.csv --output data/proxy_enrichment.csv
  python enrich_proxy_check.py --input data/triage_candidates.csv --budget 500
"""

import argparse
import csv
import json
import logging
import os
import sys
import time
from typing import Dict, List, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

PROXYCHECK_API = "https://proxycheck.io/v2"
DEFAULT_BUDGET = 900  # Stay under 1,000 free daily limit
BATCH_SIZE = 100  # proxycheck.io supports up to 1000 IPs per POST request

# Also load IPIDEA C2 domains for local matching
IPIDEA_DOMAINS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "ipidea_c2_domains.txt"
)


def load_ipidea_domains() -> set:
    """Load IPIDEA C2 and proxy brand domains for local matching."""
    if not os.path.exists(IPIDEA_DOMAINS_PATH):
        return set()
    with open(IPIDEA_DOMAINS_PATH) as f:
        return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}


def check_ips_batch(ips: List[str], api_key: str = "") -> Dict[str, Dict]:
    """Query proxycheck.io for a batch of IPs via individual GET requests.
    Returns {ip: result_dict}."""
    results = {}
    for ip in ips:
        params = {"vpn": "1", "asn": "1", "risk": "1"}
        if api_key:
            params["key"] = api_key
        try:
            resp = requests.get(f"{PROXYCHECK_API}/{ip}", params=params, timeout=15)
            if resp.status_code == 429:
                logger.warning("proxycheck.io rate limited; waiting 60s")
                time.sleep(60)
                continue
            if resp.status_code != 200:
                continue
            data = resp.json()
            if data.get("status") == "ok" and ip in data:
                entry = data[ip]
                results[ip] = {
                    "proxy_detected": entry.get("proxy", "no"),
                    "proxy_type": entry.get("type", ""),
                    "proxy_risk": str(entry.get("risk", "")),
                    "proxy_provider": entry.get("provider", ""),
                    "proxy_asn": entry.get("asn", ""),
                }
        except Exception as e:
            logger.debug(f"proxycheck.io failed for {ip}: {e}")
    return results


def check_single_ip(ip: str, api_key: str = "") -> Dict:
    """Query proxycheck.io for a single IP."""
    params = {"vpn": "1", "asn": "1", "risk": "1"}
    if api_key:
        params["key"] = api_key

    try:
        resp = requests.get(f"{PROXYCHECK_API}/{ip}", params=params, timeout=15)
        if resp.status_code == 429:
            return {}
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "ok" and ip in data:
            entry = data[ip]
            return {
                "proxy_detected": entry.get("proxy", "no"),
                "proxy_type": entry.get("type", ""),
                "proxy_risk": str(entry.get("risk", "")),
                "proxy_provider": entry.get("provider", ""),
                "proxy_asn": entry.get("asn", ""),
            }
    except Exception:
        pass
    return {}


def enrich_csv(input_path: str, output_path: str, api_key: str, budget: int,
               ip_column: str = "a_record"):
    """Read input CSV, enrich IPs with proxy detection, write output."""
    ipidea_domains = load_ipidea_domains()
    logger.info(f"Loaded {len(ipidea_domains)} IPIDEA IOC domains")

    with open(input_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = list(reader.fieldnames or [])

    # Add new columns
    new_fields = ["proxy_detected", "proxy_type", "proxy_risk", "proxy_provider",
                  "ipidea_domain_match"]
    for nf in new_fields:
        if nf not in fieldnames:
            fieldnames.append(nf)

    # Collect unique IPs to check
    unique_ips = set()
    for row in rows:
        ip = row.get(ip_column, "").strip()
        if ip and ip[0].isdigit():
            unique_ips.add(ip)
        # Also check mx_ip
        mx_ip = row.get("mx_ip", "").strip()
        if mx_ip and mx_ip[0].isdigit():
            unique_ips.add(mx_ip)

    ip_list = list(unique_ips)[:budget]
    logger.info(f"Checking {len(ip_list)} unique IPs (budget: {budget})")

    # Batch query
    results = {}
    for i in range(0, len(ip_list), BATCH_SIZE):
        batch = ip_list[i:i + BATCH_SIZE]
        logger.info(f"  Batch {i // BATCH_SIZE + 1}: {len(batch)} IPs...")
        batch_results = check_ips_batch(batch, api_key)
        results.update(batch_results)
        if i + BATCH_SIZE < len(ip_list):
            time.sleep(1.0)  # Rate limit between batches

    proxy_count = sum(1 for r in results.values() if r.get("proxy_detected") == "yes")
    logger.info(f"Results: {len(results)} checked, {proxy_count} proxies detected")

    # Enrich rows
    for row in rows:
        ip = row.get(ip_column, "").strip()
        if ip in results:
            for k, v in results[ip].items():
                row[k] = v

            # Append proxy tag to risk_tags if detected
            if results[ip].get("proxy_detected") == "yes":
                ptype = results[ip].get("proxy_type", "proxy")
                existing = row.get("risk_tags", "")
                tag = f"Proxy:{ptype}"
                if tag not in existing:
                    row["risk_tags"] = f"{existing};{tag}" if existing else tag

        # IPIDEA domain matching (check domain, primary_mx against IOC list)
        ipidea_match = "FALSE"
        for field in ["domain", "primary_mx"]:
            domain = row.get(field, "").strip().lower()
            if domain:
                # Check if domain or any parent matches IPIDEA IOCs
                parts = domain.split(".")
                for j in range(len(parts) - 1):
                    candidate = ".".join(parts[j:])
                    if candidate in ipidea_domains:
                        ipidea_match = "TRUE"
                        existing = row.get("risk_tags", "")
                        tag = "IPIDEA:ResidentialProxy"
                        if tag not in existing:
                            row["risk_tags"] = f"{existing};{tag}" if existing else tag
                        break
        row["ipidea_domain_match"] = ipidea_match

    # Write output
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    logger.info(f"Wrote {len(rows)} enriched rows to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Proxy detection enrichment via proxycheck.io")
    parser.add_argument("--input", required=True, help="Input CSV path")
    parser.add_argument("--output", default=None, help="Output CSV path (default: overwrite input)")
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET,
                        help=f"Max IPs to check (default: {DEFAULT_BUDGET})")
    parser.add_argument("--ip-column", default="a_record",
                        help="Column name containing IPs (default: a_record)")
    args = parser.parse_args()

    api_key = os.environ.get("PROXYCHECK_API_KEY", "")
    if not api_key:
        logger.warning("No PROXYCHECK_API_KEY set; using unregistered tier (100/day limit)")

    output = args.output or args.input
    enrich_csv(args.input, output, api_key, args.budget, args.ip_column)


if __name__ == "__main__":
    main()
