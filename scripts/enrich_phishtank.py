#!/usr/bin/env python3
"""
enrich_phishtank.py

PhishTank & URLhaus Bulk Feed Matching.
Downloads active phishing and malware feeds, extracts domains from URLs,
and cross-references them against monitored domains.

Output columns: domain, phishtank_match, phishtank_url, urlhaus_match, urlhaus_threat
"""

import argparse
import csv
import gzip
import io
import logging
import os
import sys

from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from shodan_utils import ShodanCache
from shared.retry import retry

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Configuration ---

PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv.gz"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv/"
DEFAULT_INPUT = "data/dea_domains.csv"
DEFAULT_OUTPUT = "data/phishtank_matches.csv"
CACHE_DB_PATH = "data/.phishtank_cache/cache.db"
DATASET_TTL_DAYS = 1
OUTPUT_COLUMNS = ["domain", "phishtank_match", "phishtank_url", "urlhaus_match", "urlhaus_threat"]


# --- Core Functions ---

def extract_domain_from_url(url: str) -> str:
    """Extract and normalize the domain from a URL.

    Uses urllib.parse.urlparse, strips port numbers, and lowercases.
    Returns empty string on failure or empty input.
    """
    if not url or not url.strip():
        return ""
    try:
        parsed = urlparse(url.strip())
        netloc = parsed.netloc
        if not netloc:
            return ""
        # Strip port if present
        domain = netloc.split(":")[0]
        return domain.lower()
    except Exception:
        return ""


def parse_phishtank_csv(file_obj) -> Dict[str, str]:
    """Parse PhishTank CSV and build a domain -> URL mapping.

    Args:
        file_obj: File-like object with PhishTank CSV data (with header).

    Returns:
        Dict mapping domain -> first phishing URL seen for that domain.
    """
    domain_map = {}
    reader = csv.DictReader(file_obj)

    for row in reader:
        url = row.get("url", "").strip()
        if not url:
            continue
        domain = extract_domain_from_url(url)
        if domain and domain not in domain_map:
            domain_map[domain] = url

    logger.info("Parsed %d unique domains from PhishTank CSV", len(domain_map))
    return domain_map


def parse_urlhaus_csv(file_obj) -> Dict[str, Dict[str, str]]:
    """Parse URLhaus CSV (with comment lines) and build a domain mapping.

    URLhaus CSV has comment lines starting with #. These are skipped,
    then the remaining lines are parsed as CSV with the first non-comment
    line as the header.

    Args:
        file_obj: File-like object with URLhaus CSV data.

    Returns:
        Dict mapping domain -> {"threat": str, "url": str}.
    """
    domain_map = {}

    # Read all lines, extracting column names from comment header
    fieldnames = None
    data_lines = []
    for line in file_obj:
        # Handle both bytes and str
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")
        
        if line.startswith("#"):
            # Extract column names from "# id,dateadded,url..." comment line
            clean_line = line.lstrip("#").strip()
            if clean_line.lower().startswith("id,dateadded,url"):
                fieldnames = [c.strip() for c in clean_line.split(",")]
            elif line.lower().startswith("# columns:"):
                cols_str = line.split(":", 1)[1].strip()
                fieldnames = [c.strip() for c in cols_str.split(",")]
        else:
            data_lines.append(line)

    if not data_lines:
        return domain_map

    # Parse remaining lines as CSV with extracted or default fieldnames
    csv_text = "".join(data_lines)
    if fieldnames is None:
        # Fallback: assume first data line is a header
        reader = csv.DictReader(io.StringIO(csv_text, newline=""))
    else:
        reader = csv.DictReader(io.StringIO(csv_text, newline=""), fieldnames=fieldnames)

    for row in reader:
        url = row.get("url", "").strip()
        if not url:
            continue
        threat = row.get("threat", "").strip()
        domain = extract_domain_from_url(url)
        if domain and domain not in domain_map:
            domain_map[domain] = {"threat": threat, "url": url}

    logger.info("Parsed %d unique domains from URLhaus CSV", len(domain_map))
    return domain_map


def cross_reference_domains(
    domains: List[str],
    phishtank_map: Dict[str, str],
    urlhaus_map: Dict[str, Dict[str, str]],
) -> List[Dict[str, str]]:
    """Cross-reference a list of domains against PhishTank and URLhaus maps.

    Args:
        domains: List of domain names to check.
        phishtank_map: Domain -> URL mapping from PhishTank.
        urlhaus_map: Domain -> {"threat", "url"} mapping from URLhaus.

    Returns:
        List of result dicts for matched domains only.
    """
    results = []

    for domain in domains:
        domain_lower = domain.lower().strip()
        in_phishtank = domain_lower in phishtank_map
        in_urlhaus = domain_lower in urlhaus_map

        if in_phishtank or in_urlhaus:
            result = {
                "domain": domain,
                "phishtank_match": "True" if in_phishtank else "",
                "phishtank_url": phishtank_map.get(domain_lower, ""),
                "urlhaus_match": "True" if in_urlhaus else "",
                "urlhaus_threat": urlhaus_map.get(domain_lower, {}).get("threat", "") if in_urlhaus else "",
            }
            results.append(result)

    return results


@retry(max_attempts=3, backoff_base=2.0, exceptions=(requests.RequestException,))
def _download(url: str, timeout: int = 120) -> requests.Response:
    """Download a URL with retry and exponential backoff."""
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp


def _load_cached_feeds(cache) -> Optional[Tuple[Dict, Dict]]:
    """Load cached feed data if still fresh.

    Args:
        cache: ShodanCache instance.

    Returns:
        Tuple of (phishtank_map, urlhaus_map) if cached and fresh, else None.
    """
    meta = cache.get("_feed_meta", max_age_days=DATASET_TTL_DAYS)
    if meta is None:
        return None

    phishtank_map = cache.get("_phishtank_domains", max_age_days=DATASET_TTL_DAYS)
    urlhaus_map = cache.get("_urlhaus_domains", max_age_days=DATASET_TTL_DAYS)

    if phishtank_map is not None and urlhaus_map is not None:
        logger.info(
            "Using cached feeds: %d PhishTank, %d URLhaus domains",
            len(phishtank_map),
            len(urlhaus_map),
        )
        return phishtank_map, urlhaus_map

    return None


def build_bad_domain_set(cache=None) -> Tuple[Dict, Dict]:
    """Download and parse PhishTank and URLhaus feeds.

    Uses caching to avoid re-downloading within DATASET_TTL_DAYS.
    If one feed fails, continues with the other.

    Args:
        cache: Optional ShodanCache instance for caching.

    Returns:
        Tuple of (phishtank_map, urlhaus_map).
    """
    # Check cache first
    if cache is not None:
        cached = _load_cached_feeds(cache)
        if cached is not None:
            return cached

    phishtank_map = {}
    urlhaus_map = {}

    # Download PhishTank (gzipped CSV)
    try:
        logger.info("Downloading PhishTank feed from %s", PHISHTANK_URL)
        resp = _download(PHISHTANK_URL)
        raw_csv = gzip.decompress(resp.content)
        phishtank_map = parse_phishtank_csv(io.StringIO(raw_csv.decode("utf-8", errors="replace")))
    except Exception as e:
        logger.error("Failed to download/parse PhishTank feed: %s", e)

    # Download URLhaus (ZIP with csv.txt)
    try:
        logger.info("Downloading URLhaus feed from %s", URLHAUS_URL)
        resp = _download(URLHAUS_URL)
        import zipfile
        with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
            csv_data = z.read("csv.txt").decode("utf-8", errors="replace")
        urlhaus_map = parse_urlhaus_csv(io.StringIO(csv_data))
    except Exception as e:
        logger.error("Failed to download/parse URLhaus feed: %s", e)

    # Cache results
    if cache is not None:
        cache.set("_phishtank_domains", phishtank_map)
        cache.set("_urlhaus_domains", urlhaus_map)
        cache.set("_feed_meta", {
            "phishtank_count": len(phishtank_map),
            "urlhaus_count": len(urlhaus_map),
        })

    return phishtank_map, urlhaus_map


def run(input_file: str, output_file: str) -> int:
    """Run the PhishTank & URLhaus enrichment pipeline.

    Args:
        input_file: Input CSV path (must have a 'domain' column).
        output_file: Output CSV path.

    Returns:
        Number of matched domains.
    """
    if not os.path.isfile(input_file):
        logger.error("Input file not found: %s", input_file)
        return 0

    # Read input domains
    with open(input_file, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    domains = [row.get("domain", "").strip() for row in rows if row.get("domain", "").strip()]

    if not domains:
        logger.warning("No domains found in input file")
        return 0

    # Init cache
    cache_dir = os.path.dirname(CACHE_DB_PATH) or "."
    os.makedirs(cache_dir, exist_ok=True)
    cache = ShodanCache(db_path=CACHE_DB_PATH)

    try:
        phishtank_map, urlhaus_map = build_bad_domain_set(cache=cache)
        results = cross_reference_domains(domains, phishtank_map, urlhaus_map)

        # Write output
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
            writer.writeheader()
            writer.writerows(results)

        logger.info(
            "Found %d domain matches. Output: %s", len(results), output_file
        )
        return len(results)
    finally:
        cache.close()


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="PhishTank & URLhaus Bulk Feed Matching"
    )
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Input CSV file")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output CSV file")
    args = parser.parse_args()

    count = run(args.input, args.output)
    logger.info("Done. %d domains matched.", count)


if __name__ == "__main__":
    main()
