#!/usr/bin/env python3
"""
enrich_securitytrails.py

Manual single-domain SecurityTrails investigation tool.
Queries historical DNS (A, MX, NS) and WHOIS via SecurityTrails API v1.
Hard circuit breaker at 50 queries per 30-day rolling window.

Usage:
    python scripts/enrich_securitytrails.py --domain evil.com [--save] [--budget-check]

NOT for automated pipeline use. Deliberately excluded from CI.
"""

import argparse
import csv
import logging
import os
import sys
from typing import Dict, Optional

import requests
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from shodan_utils import ShodanCache
from shared.retry import retry
from shared.api_budget import PersistentQuotaTracker

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ST_API_BASE = "https://api.securitytrails.com/v1"
CACHE_DB_PATH = "data/.securitytrails_cache/cache.db"
BUDGET_DB_PATH = "data/.securitytrails_cache/budget.db"
CACHE_TTL_DAYS = 30
MAX_QUERIES_30D = 50
DEFAULT_CSV_PATH = "data/manual_investigations.csv"

ST_COLUMNS = [
    "domain",
    "st_dns_history_count",
    "st_registrar_changes",
    "st_mx_history",
    "st_first_seen",
    "st_mx_change_date",
]

DNS_RECORD_TYPES = ["a", "mx", "ns"]

# Value key per record type in SecurityTrails response
VALUE_KEYS = {
    "a": "ip",
    "mx": "host",
    "ns": "nameserver",
}


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

@retry(max_attempts=3, backoff_base=2.0, exceptions=(requests.RequestException,))
def _st_api_get(endpoint: str, api_key: str) -> Optional[dict]:
    """Make a GET request to SecurityTrails API."""
    url = f"{ST_API_BASE}/{endpoint}"
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code == 429:
        raise requests.RequestException(f"Rate limited (429) on {endpoint}")
    if resp.status_code == 403:
        logger.error("API key invalid or quota exceeded (403)")
        return None
    if resp.status_code == 404:
        logger.warning("No data found for endpoint: %s", endpoint)
        return None
    resp.raise_for_status()
    return resp.json()


def query_domain(domain: str, api_key: str, tracker: PersistentQuotaTracker,
                 cache: ShodanCache) -> Dict[str, Optional[dict]]:
    """Query all 4 SecurityTrails endpoints for a domain.

    Returns dict: {"history/{domain}/dns/a": {...}, ...}
    Uses cache when available. Records usage in tracker for each uncached call.
    """
    endpoints = [f"history/{domain}/dns/{t}" for t in DNS_RECORD_TYPES]
    endpoints.append(f"history/{domain}/whois")

    results = {}
    for ep in endpoints:
        suffix = ep.split(f"{domain}/", 1)[1]  # "dns/a", "dns/mx", "dns/ns", "whois"
        cache_key = f"st:{domain}:{suffix}"
        cached = cache.get(cache_key, max_age_days=CACHE_TTL_DAYS)
        if cached is not None:
            logger.info("Cache hit: %s", cache_key)
            results[ep] = cached
            continue

        # Pre-flight budget check for this single call
        if not tracker.can_spend(1):
            logger.error("Budget exhausted — skipping %s", ep)
            results[ep] = None
            continue

        data = _st_api_get(ep, api_key)
        tracker.record_usage("securitytrails", domain, cost=1)
        # Conservative accounting: record usage even on 403/404 since the
        # SecurityTrails API counts any request against the free-tier quota.

        if data is not None:
            cache.set(cache_key, data)
        else:
            cache.set(cache_key, {})  # cache 404/empty to avoid re-query

        results[ep] = data

    return results


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------

def parse_dns_history(data: Optional[dict], record_type: str) -> dict:
    """Parse a SecurityTrails DNS history response.

    Returns: {unique_count, first_seen, last_change, entries: [{value, first_seen, last_seen}]}
    """
    empty = {"unique_count": 0, "first_seen": "", "last_change": "", "entries": []}
    if not data or "records" not in data:
        return empty

    records = data["records"]
    if not records:
        return empty

    value_key = VALUE_KEYS.get(record_type, "ip")
    entries = []
    for rec in records:
        values = rec.get("values", [])
        val = values[0].get(value_key, "") if values else ""
        entries.append({
            "value": val,
            "first_seen": rec.get("first_seen", ""),
            "last_seen": rec.get("last_seen", ""),
        })

    # Sort by first_seen ascending
    entries.sort(key=lambda e: e["first_seen"])

    first_seen = entries[0]["first_seen"] if entries else ""
    # last_change = the first_seen of the most recent entry (when the change happened)
    last_change = entries[-1]["first_seen"] if len(entries) > 1 else ""

    return {
        "unique_count": len(entries),
        "first_seen": first_seen,
        "last_change": last_change,
        "entries": entries,
    }


def parse_whois_history(data: Optional[dict]) -> dict:
    """Parse a SecurityTrails WHOIS history response.

    Returns: {registrar_changes, entries: [{registrar, date}]}
    """
    empty = {"registrar_changes": 0, "entries": []}
    if not data:
        return empty

    items = []
    try:
        items = data.get("result", {}).get("items", [])
    except AttributeError:
        return empty

    if not items:
        return empty

    entries = []
    for item in items:
        entries.append({
            "registrar": item.get("registrar_name", "Unknown"),
            "date": item.get("created_date", ""),
        })

    entries.sort(key=lambda e: e["date"])

    return {
        "registrar_changes": len(entries),
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# Output builders
# ---------------------------------------------------------------------------

def build_result_row(domain: str, dns_a: dict, dns_mx: dict,
                     dns_ns: dict, whois: dict) -> dict:
    """Build the flat dict for CSV output."""
    mx_providers = []
    for entry in dns_mx.get("entries", []):
        val = entry.get("value", "")
        # Extract domain from MX hostname (e.g., mx1.google.com -> google.com)
        parts = val.split(".")
        if len(parts) >= 2:
            provider = ".".join(parts[-2:])
            if provider not in mx_providers:
                mx_providers.append(provider)

    return {
        "domain": domain,
        "st_dns_history_count": str(dns_a.get("unique_count", 0)),
        "st_registrar_changes": str(whois.get("registrar_changes", 0)),
        "st_mx_history": ";".join(mx_providers),
        "st_first_seen": dns_a.get("first_seen", ""),
        "st_mx_change_date": dns_mx.get("last_change", ""),
    }


def format_console_output(domain: str, dns_a: dict, dns_mx: dict,
                          dns_ns: dict, whois: dict, remaining: int) -> str:
    """Format investigation results for console display."""
    lines = []
    sep = "=" * 50
    lines.append(sep)
    lines.append(f" SecurityTrails Investigation: {domain}")
    lines.append(sep)
    lines.append(f" Budget: {remaining}/{MAX_QUERIES_30D} remaining")
    lines.append("")

    # A Records
    lines.append(f" DNS History (A Records): {dns_a['unique_count']} unique IPs")
    lines.append(" " + "-" * 35)
    for i, entry in enumerate(dns_a.get("entries", [])):
        tag = ""
        if i == 0:
            tag = "  (first seen)"
        lines.append(f"   {entry['first_seen']}  {entry['value']}{tag}")
    lines.append("")

    # MX Records
    lines.append(f" MX History: {dns_mx['unique_count']} changes")
    lines.append(" " + "-" * 35)
    for entry in dns_mx.get("entries", []):
        lines.append(f"   {entry['first_seen']}  {entry['value']}")
    lines.append("")

    # NS Records
    lines.append(f" NS History: {dns_ns['unique_count']} changes")
    lines.append(" " + "-" * 35)
    for entry in dns_ns.get("entries", []):
        lines.append(f"   {entry['first_seen']}  {entry['value']}")
    lines.append("")

    # WHOIS
    lines.append(f" WHOIS History: {whois['registrar_changes']} registrar changes")
    lines.append(" " + "-" * 35)
    for entry in whois.get("entries", []):
        lines.append(f"   {entry['date']}  {entry['registrar']}")

    lines.append(sep)
    return "\n".join(lines)


def save_to_csv(row: dict, csv_path: str = DEFAULT_CSV_PATH):
    """Append a result row to the manual investigations CSV."""
    file_exists = os.path.isfile(csv_path)
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ST_COLUMNS)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)
    logger.info("Results saved to %s", csv_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    load_dotenv()
    api_key = os.getenv("ST_API_KEY", "")

    parser = argparse.ArgumentParser(
        description="SecurityTrails manual domain investigation tool (50 queries / 30 days)"
    )
    parser.add_argument("--domain", required=False, help="Domain to investigate")
    parser.add_argument("--save", action="store_true", help="Append results to manual_investigations.csv")
    parser.add_argument("--budget-check", action="store_true", help="Print remaining quota and exit")
    args = parser.parse_args()

    tracker = PersistentQuotaTracker(
        db_path=BUDGET_DB_PATH, max_queries=MAX_QUERIES_30D, window_days=30
    )

    if args.budget_check:
        remaining = tracker.get_remaining()
        used = tracker.get_usage()
        print(f"SecurityTrails budget: {remaining}/{MAX_QUERIES_30D} remaining ({used} used in last 30 days)")
        tracker.close()
        return

    if not args.domain:
        parser.error("--domain is required (unless using --budget-check)")

    if not api_key:
        logger.error("ST_API_KEY not set in environment or .env")
        sys.exit(1)

    # Pre-flight: ensure we have budget for 4 API calls
    tracker.abort_if_exceeded(4)

    cache = ShodanCache(db_path=CACHE_DB_PATH)

    # Query all endpoints
    results = query_domain(args.domain, api_key, tracker, cache)

    # Parse responses
    dns_a_key = f"history/{args.domain}/dns/a"
    dns_mx_key = f"history/{args.domain}/dns/mx"
    dns_ns_key = f"history/{args.domain}/dns/ns"
    whois_key = f"history/{args.domain}/whois"

    dns_a = parse_dns_history(results.get(dns_a_key), "a")
    dns_mx = parse_dns_history(results.get(dns_mx_key), "mx")
    dns_ns = parse_dns_history(results.get(dns_ns_key), "ns")
    whois = parse_whois_history(results.get(whois_key))

    # Display
    remaining = tracker.get_remaining()
    output = format_console_output(args.domain, dns_a, dns_mx, dns_ns, whois, remaining)
    print(output)

    # Build row and optionally save
    row = build_result_row(args.domain, dns_a, dns_mx, dns_ns, whois)
    if args.save:
        save_to_csv(row)

    cache.close()
    tracker.close()


if __name__ == "__main__":
    main()
