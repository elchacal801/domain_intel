#!/usr/bin/env python3
"""
enrich_gleif.py

GLEIF Entity Legitimacy Verification.
Queries the Global Legal Entity Identifier Foundation API to check if
domain registrants are known, active businesses.

Reads org names from dea_domains_probed.csv (prefers registrant_org,
falls back to ssl_org). Deduplicates, queries GLEIF with caching and
rate limiting, appends 5 new columns.
"""

import argparse
import csv
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from shodan_utils import ShodanCache
from shared.retry import retry

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Configuration ---

GLEIF_API_BASE = "https://api.gleif.org/api/v1/lei-records"
DEFAULT_INPUT = "data/dea_domains_probed.csv"
DEFAULT_OUTPUT = "data/dea_domains_probed.csv"
CACHE_DB_PATH = "data/.gleif_cache/cache.db"
CACHE_TTL_DAYS = 7
RATE_DELAY = 0.5  # seconds between API requests

GLEIF_COLUMNS = ["gleif_lei", "gleif_status", "gleif_legal_name", "gleif_jurisdiction", "gleif_has_parent"]

EMPTY_RESULT = {
    "gleif_lei": "",
    "gleif_status": "",
    "gleif_legal_name": "",
    "gleif_jurisdiction": "",
    "gleif_has_parent": "",
}


# --- Core Functions ---

def get_org_name(row: Dict[str, str]) -> str:
    """Extract the best org name from a domain row.

    Prefers registrant_org (from RDAP), falls back to ssl_org.
    """
    org = row.get("registrant_org", "").strip()
    if org:
        return org
    return row.get("ssl_org", "").strip()


def parse_gleif_response(response_json: Dict[str, Any]) -> Dict[str, str]:
    """Parse a GLEIF API response into a flat dict of enrichment fields.

    Args:
        response_json: The parsed JSON from the GLEIF API.

    Returns:
        Dict with gleif_lei, gleif_status, gleif_legal_name,
        gleif_jurisdiction, gleif_has_parent.
    """
    data = response_json.get("data", [])
    if not data:
        return dict(EMPTY_RESULT)

    record = data[0]
    attrs = record.get("attributes", {})
    entity = attrs.get("entity", {})
    legal_name_obj = entity.get("legalName", {})

    # Check for parent relationship
    relationships = record.get("relationships", {})
    has_parent = "True" if "direct-parent" in relationships else "False"

    return {
        "gleif_lei": attrs.get("lei", ""),
        "gleif_status": entity.get("status", ""),
        "gleif_legal_name": legal_name_obj.get("name", "") if isinstance(legal_name_obj, dict) else str(legal_name_obj),
        "gleif_jurisdiction": entity.get("jurisdiction", ""),
        "gleif_has_parent": has_parent,
    }


@retry(max_attempts=3, backoff_base=2.0, exceptions=(requests.RequestException,))
def _gleif_api_call(url: str, params: Dict[str, str]) -> requests.Response:
    """Make a GLEIF API call with retry on transient failures."""
    return requests.get(url, params=params, timeout=15)


def query_gleif(
    org_name: str,
    cache: Optional[Any] = None,
    rate_delay: float = RATE_DELAY,
) -> Dict[str, str]:
    """Query GLEIF for an organization name, with caching and rate limiting.

    Args:
        org_name: The organization name to look up.
        cache: ShodanCache instance (or mock). If None, no caching.
        rate_delay: Seconds to sleep between API calls.

    Returns:
        Dict with GLEIF enrichment fields.
    """
    cache_key = f"org:{org_name.lower().strip()}"

    # Check cache
    if cache:
        cached = cache.get(cache_key, max_age_days=CACHE_TTL_DAYS)
        if cached is not None:
            return cached

    # Rate limit
    time.sleep(rate_delay)

    # Primary: exact legal name match
    try:
        resp = _gleif_api_call(GLEIF_API_BASE, {"filter[entity.legalName]": org_name})
        if resp.status_code == 200:
            result = parse_gleif_response(resp.json())
            if result["gleif_lei"]:
                if cache:
                    cache.set(cache_key, result)
                return result
    except requests.RequestException as e:
        logger.warning("GLEIF exact search failed for '%s': %s", org_name, e)

    # Fallback: fulltext search
    try:
        resp = _gleif_api_call(GLEIF_API_BASE, {"filter[fulltext]": org_name})
        if resp.status_code == 200:
            result = parse_gleif_response(resp.json())
            if cache:
                cache.set(cache_key, result)
            return result
    except requests.RequestException as e:
        logger.warning("GLEIF fulltext search failed for '%s': %s", org_name, e)

    # No result — cache the empty to avoid re-querying
    empty = dict(EMPTY_RESULT)
    if cache:
        cache.set(cache_key, empty)
    return empty


def build_org_lookup(
    rows: List[Dict[str, str]],
    cache: Optional[Any] = None,
    rate_delay: float = RATE_DELAY,
    limit: int = 0,
) -> Dict[str, Dict[str, str]]:
    """Build a lookup table of org_name -> GLEIF result for all unique orgs.

    Args:
        rows: List of domain CSV row dicts.
        cache: ShodanCache instance.
        rate_delay: Seconds between API calls.
        limit: Max orgs to query (0 = unlimited).

    Returns:
        Dict mapping normalized org name -> GLEIF result dict.
    """
    # Collect unique org names
    unique_orgs = set()
    for row in rows:
        org = get_org_name(row)
        if org:
            unique_orgs.add(org)

    org_list = sorted(unique_orgs)
    if limit > 0:
        org_list = org_list[:limit]

    logger.info("Found %d unique org names to query GLEIF", len(org_list))

    lookup = {}
    for i, org in enumerate(org_list):
        logger.info("[%d/%d] Querying GLEIF: %s", i + 1, len(org_list), org[:60])
        result = query_gleif(org, cache=cache, rate_delay=rate_delay)
        lookup[org] = result
        if result["gleif_lei"]:
            logger.info("  -> Found LEI: %s (%s)", result["gleif_lei"], result["gleif_status"])

    return lookup


# --- Main ---

def run(input_file: str, output_file: str, limit: int = 0) -> int:
    """Run the GLEIF enrichment pipeline.

    Returns:
        Number of domains enriched with GLEIF data.
    """
    if not os.path.isfile(input_file):
        logger.error("Input file not found: %s", input_file)
        return 0

    # Read input
    with open(input_file, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames) if reader.fieldnames else []
        rows = list(reader)

    if not rows:
        logger.warning("No rows in input file")
        return 0

    # Init cache
    os.makedirs(os.path.dirname(CACHE_DB_PATH) or ".", exist_ok=True)
    cache = ShodanCache(db_path=CACHE_DB_PATH)

    try:
        # Build org lookup
        lookup = build_org_lookup(rows, cache=cache, rate_delay=RATE_DELAY, limit=limit)

        # Enrich rows
        enriched_count = 0
        for col in GLEIF_COLUMNS:
            if col not in fieldnames:
                fieldnames.append(col)

        for row in rows:
            org = get_org_name(row)
            if org and org in lookup:
                gleif_data = lookup[org]
                for col in GLEIF_COLUMNS:
                    row[col] = gleif_data.get(col, "")
                if gleif_data.get("gleif_lei"):
                    enriched_count += 1
            else:
                for col in GLEIF_COLUMNS:
                    row.setdefault(col, "")

        # Write output
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        logger.info("Enriched %d domains with GLEIF data. Output: %s", enriched_count, output_file)
        return enriched_count
    finally:
        cache.close()


def main():
    parser = argparse.ArgumentParser(description="GLEIF Entity Verification Enrichment")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Input CSV file")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output CSV file")
    parser.add_argument("--limit", type=int, default=0, help="Max orgs to query (0=all)")
    args = parser.parse_args()

    count = run(args.input, args.output, args.limit)
    logger.info("Done. %d domains enriched.", count)


if __name__ == "__main__":
    main()
