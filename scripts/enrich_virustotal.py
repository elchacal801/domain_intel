#!/usr/bin/env python3
"""
enrich_virustotal.py

VirusTotal API v3 domain enrichment.
Queries VT for each domain in the triage candidates CSV and appends
threat intelligence columns (malicious engine count, reputation score,
last analysis date).
"""

import argparse
import csv
import logging
import os
import sys
import time
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from shodan_utils import ShodanCache, CreditBudget
from shared.retry import retry

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VT_API_BASE = "https://www.virustotal.com/api/v3/domains"
DEFAULT_INPUT = "data/triage_candidates.csv"
DEFAULT_OUTPUT = "data/virustotal_intelligence.csv"
CACHE_DB_PATH = "data/.vt_cache/cache.db"
CACHE_TTL_DAYS = 7
DEFAULT_BUDGET = 500
DEFAULT_RPM = 4  # requests per minute, VT free tier

VT_COLUMNS = [
    "vt_malicious_count",
    "vt_total_engines",
    "vt_reputation",
    "vt_last_analysis_date",
]

EMPTY_RESULT: Dict[str, str] = {col: "" for col in VT_COLUMNS}


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Thread-safe rate limiter based on requests per minute."""

    def __init__(self, requests_per_minute: float):
        self._interval = 60.0 / requests_per_minute
        self._lock = threading.Lock()
        self._last_call: float = 0.0

    def wait(self):
        """Block until the minimum interval has elapsed since the last call."""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_call
            to_wait = self._interval - elapsed
            if to_wait > 0:
                time.sleep(to_wait)
            self._last_call = time.time()


# ---------------------------------------------------------------------------
# VT response parser
# ---------------------------------------------------------------------------

def parse_vt_response(data: dict) -> Dict[str, str]:
    """Parse a VirusTotal API v3 JSON response into flat column values.

    Args:
        data: The full JSON dict returned by VT /domains/{domain}.

    Returns:
        Dict with keys matching VT_COLUMNS.
    """
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    reputation = attrs.get("reputation", "")
    analysis_epoch = attrs.get("last_analysis_date")

    if analysis_epoch:
        analysis_date = datetime.fromtimestamp(analysis_epoch, tz=timezone.utc).strftime("%Y-%m-%d")
    else:
        analysis_date = ""

    return {
        "vt_malicious_count": str(malicious),
        "vt_total_engines": str(total),
        "vt_reputation": str(reputation) if reputation != "" else "",
        "vt_last_analysis_date": analysis_date,
    }


# ---------------------------------------------------------------------------
# Retry-wrapped API call
# ---------------------------------------------------------------------------

@retry(max_attempts=3, backoff_base=5.0, exceptions=(requests.RequestException,))
def _vt_api_get(url: str, headers: dict) -> requests.Response:
    """GET request to VT API with retry on transient errors."""
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 429:
        raise requests.RequestException(
            f"Rate limited (429), Retry-After: {resp.headers.get('Retry-After', 'unknown')}"
        )
    return resp


# ---------------------------------------------------------------------------
# Query function
# ---------------------------------------------------------------------------

def query_virustotal(
    domain: str,
    api_key: str,
    cache: Any,
    budget: Any,
    rate_limiter: RateLimiter,
) -> Dict[str, str]:
    """Query VirusTotal for a single domain.

    Checks cache first, respects budget and rate limits.

    Args:
        domain: The domain name to look up.
        api_key: VT API key.
        cache: ShodanCache instance.
        budget: CreditBudget instance.
        rate_limiter: RateLimiter instance.

    Returns:
        Dict with VT_COLUMNS keys populated, or EMPTY_RESULT on failure.
    """
    cache_key = f"vt:{domain}"

    # 1. Cache check
    cached = cache.get(cache_key, max_age_days=CACHE_TTL_DAYS)
    if cached is not None:
        logger.debug("Cache HIT for %s", domain)
        return cached

    # 2. Budget check
    if not budget.check_can_spend(1):
        logger.warning("Budget exhausted — skipping %s", domain)
        return dict(EMPTY_RESULT)

    # 3. Rate limit
    rate_limiter.wait()

    # 4. Spend budget and call API
    try:
        budget.spend(1)
    except RuntimeError:
        logger.warning("Budget exhausted during spend — skipping %s", domain)
        return dict(EMPTY_RESULT)
    url = f"{VT_API_BASE}/{domain}"
    headers = {"x-apikey": api_key}

    try:
        resp = _vt_api_get(url, headers)
    except requests.RequestException as exc:
        logger.error("API request failed for %s: %s", domain, exc)
        return dict(EMPTY_RESULT)

    # 5. 200 — success
    if resp.status_code == 200:
        parsed = parse_vt_response(resp.json())
        cache.set(cache_key, parsed)
        return parsed

    # 6. 404 — domain not found in VT
    if resp.status_code == 404:
        logger.info("VT 404 for %s — caching empty", domain)
        empty = dict(EMPTY_RESULT)
        cache.set(cache_key, empty)
        return empty

    # 7. 401 — bad key / unauthorised (do NOT cache)
    if resp.status_code == 401:
        logger.error("VT 401 Unauthorized for %s — check API key", domain)
        return dict(EMPTY_RESULT)

    # 8. Other status codes
    logger.warning("VT returned %d for %s", resp.status_code, domain)
    return dict(EMPTY_RESULT)


# ---------------------------------------------------------------------------
# Run pipeline
# ---------------------------------------------------------------------------

def run(
    input_file: str,
    output_file: str,
    api_key: str,
    budget_limit: int = DEFAULT_BUDGET,
    rpm: float = DEFAULT_RPM,
    limit: int = 0,
) -> int:
    """Run the VirusTotal enrichment pipeline.

    Args:
        input_file: Path to triage_candidates.csv (or similar).
        output_file: Path for enriched output CSV.
        api_key: VT API key.
        budget_limit: Max API calls this run.
        rpm: Requests per minute rate limit.
        limit: Max domains to process (0 = all).

    Returns:
        Count of domains with malicious > 0.
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

    if limit > 0:
        rows = rows[:limit]

    # Init cache, budget, rate limiter
    cache_dir = os.path.dirname(CACHE_DB_PATH) or "."
    os.makedirs(cache_dir, exist_ok=True)
    cache = ShodanCache(db_path=CACHE_DB_PATH)

    budget = CreditBudget()
    budget.set_budget(budget_limit)

    rate_limiter = RateLimiter(requests_per_minute=rpm)

    # Ensure VT columns in fieldnames
    for col in VT_COLUMNS:
        if col not in fieldnames:
            fieldnames.append(col)

    malicious_count = 0

    try:
        for i, row in enumerate(rows):
            domain = row.get("domain", "").strip()
            if not domain:
                for col in VT_COLUMNS:
                    row.setdefault(col, "")
                continue

            if (i + 1) % 10 == 0:
                logger.info("[%d/%d] Processing VT queries...", i + 1, len(rows))

            vt_data = query_virustotal(domain, api_key, cache, budget, rate_limiter)
            for col in VT_COLUMNS:
                row[col] = vt_data.get(col, "")

            # Count domains with malicious > 0
            try:
                if int(vt_data.get("vt_malicious_count", "0") or "0") > 0:
                    malicious_count += 1
            except (ValueError, TypeError):
                pass

        # Write output
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        logger.info(
            "VT enrichment complete. %d/%d domains flagged malicious. Output: %s",
            malicious_count, len(rows), output_file,
        )
    finally:
        cache.close()

    return malicious_count


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    """CLI entry point."""
    load_dotenv()
    api_key = os.getenv("VT_API_KEY", "")

    parser = argparse.ArgumentParser(description="VirusTotal domain enrichment")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Input CSV file")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output CSV file")
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET, help="Max API credits")
    parser.add_argument("--limit", type=int, default=0, help="Max domains to process (0=all)")
    parser.add_argument("--rpm", type=float, default=DEFAULT_RPM, help="Requests per minute")
    args = parser.parse_args()

    if not api_key:
        logger.error("VT_API_KEY not set in environment or .env")
        sys.exit(1)

    count = run(args.input, args.output, api_key, args.budget, args.rpm, args.limit)
    logger.info("Done. %d domains with malicious detections.", count)


if __name__ == "__main__":
    main()
