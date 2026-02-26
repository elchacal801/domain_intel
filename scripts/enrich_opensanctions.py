#!/usr/bin/env python3
"""
enrich_opensanctions.py

OpenSanctions Entity Screening.
Downloads the OpenSanctions consolidated dataset, loads entity names
into memory, and fuzzy-matches domain registrant organizations against
sanctioned entities using Levenshtein distance.

Output columns: os_match_score, os_entity_type, os_dataset, os_entity_id
"""

import argparse
import csv
import io
import logging
import os
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

import requests
from Levenshtein import ratio as levenshtein_ratio

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from shodan_utils import ShodanCache
from shared.retry import retry

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Configuration ---

OPENSANCTIONS_URL = "https://data.opensanctions.org/datasets/latest/default/targets.simple.csv"
DEFAULT_INPUT = "data/dea_domains_probed.csv"
DEFAULT_OUTPUT = "data/dea_domains_probed.csv"
CACHE_DB_PATH = "data/.opensanctions_cache/cache.db"
DATASET_TTL_DAYS = 1   # re-download dataset every 24 hours
CACHE_TTL_DAYS = 1     # per-org match cache TTL matches dataset TTL
MATCH_THRESHOLD = 70   # minimum Levenshtein score (0-100) to count as a match

OS_COLUMNS = ["os_match_score", "os_entity_type", "os_dataset", "os_entity_id"]

EMPTY_RESULT = {
    "os_match_score": "",
    "os_entity_type": "",
    "os_dataset": "",
    "os_entity_id": "",
}


# --- Core Functions ---

def get_org_name(row: Dict[str, str]) -> str:
    """Extract the best org name from a domain row."""
    org = row.get("registrant_org", "").strip()
    if org:
        return org
    return row.get("ssl_org", "").strip()


def parse_opensanctions_csv(file_obj) -> List[Dict[str, str]]:
    """Parse OpenSanctions targets.simple.csv into a list of name entries.

    Expands aliases so each name variant is a separate entry pointing
    to the same entity_id. All names are lowercased for matching.

    Args:
        file_obj: File-like object (open file or StringIO) with CSV data.

    Returns:
        List of dicts with keys: name, entity_id, entity_type, dataset.
    """
    entries = []
    reader = csv.DictReader(file_obj)

    for row in reader:
        entity_id = row.get("id", "")
        entity_type = row.get("schema", "")
        name = row.get("name", "").strip()
        aliases_raw = row.get("aliases", "")
        dataset = row.get("dataset", "")

        if not name:
            continue

        # Primary name
        entries.append({
            "name": name.lower(),
            "entity_id": entity_id,
            "entity_type": entity_type,
            "dataset": dataset,
        })

        # Expand aliases
        if aliases_raw:
            for alias in aliases_raw.split(";"):
                alias = alias.strip()
                if alias:
                    entries.append({
                        "name": alias.lower(),
                        "entity_id": entity_id,
                        "entity_type": entity_type,
                        "dataset": dataset,
                    })

    logger.info("Parsed %d name entries from OpenSanctions CSV", len(entries))
    return entries


@retry(max_attempts=3, backoff_base=2.0, exceptions=(requests.RequestException,))
def _download_csv(url: str) -> requests.Response:
    """Download a CSV file with retry."""
    return requests.get(url, stream=True, timeout=120)


def download_and_parse(
    url: str = OPENSANCTIONS_URL,
    cache_dir: str = "",
) -> List[Dict[str, str]]:
    """Download OpenSanctions CSV and parse into entries.

    Uses streaming download to handle the ~459 MB file without loading
    it all into memory at once. Writes to a temp file, then parses.

    Args:
        url: URL to download from.
        cache_dir: Directory for temp file storage.

    Returns:
        List of parsed name entries.
    """
    logger.info("Downloading OpenSanctions dataset from %s", url)

    resp = _download_csv(url)
    if resp.status_code != 200:
        logger.error("Download failed with status %d", resp.status_code)
        return []

    # Stream to temp file to avoid memory issues
    tmp_dir = cache_dir or tempfile.gettempdir()
    os.makedirs(tmp_dir, exist_ok=True)
    tmp_path = os.path.join(tmp_dir, "targets.simple.csv")

    try:
        with open(tmp_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)

        logger.info("Downloaded to %s, parsing...", tmp_path)

        with open(tmp_path, "r", encoding="utf-8-sig", errors="replace") as f:
            entries = parse_opensanctions_csv(f)

        return entries
    finally:
        # Clean up temp file
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def fuzzy_match_org(
    org_name: str,
    entries: List[Dict[str, str]],
) -> Optional[Dict[str, str]]:
    """Fuzzy-match an org name against the OpenSanctions entries.

    Uses Levenshtein ratio scoring. Returns the best match above
    MATCH_THRESHOLD, or None.

    Args:
        org_name: The organization name to match.
        entries: Parsed OpenSanctions entries.

    Returns:
        Dict with os_match_score, os_entity_type, os_dataset, os_entity_id,
        or None if no match above threshold.
    """
    org_lower = org_name.lower().strip()
    if not org_lower:
        return None

    best_score = 0
    best_entry = None

    for entry in entries:
        score = int(levenshtein_ratio(org_lower, entry["name"]) * 100)
        if score > best_score:
            best_score = score
            best_entry = entry

        # Short-circuit on exact match
        if score == 100:
            break

    if best_score >= MATCH_THRESHOLD and best_entry is not None:
        # Truncate dataset to first entry for readability
        dataset = best_entry["dataset"].split(";")[0] if best_entry["dataset"] else ""
        return {
            "os_match_score": str(best_score),
            "os_entity_type": best_entry["entity_type"],
            "os_dataset": dataset,
            "os_entity_id": best_entry["entity_id"],
        }

    return None


def build_org_lookup(
    rows: List[Dict[str, str]],
    entries: List[Dict[str, str]],
    cache: Optional[Any] = None,
    use_cache: bool = True,
    limit: int = 0,
) -> Dict[str, Dict[str, str]]:
    """Build lookup table of org_name -> OpenSanctions match result.

    Args:
        rows: Domain CSV row dicts.
        entries: Parsed OpenSanctions entries.
        cache: ShodanCache instance.
        use_cache: Whether to use per-org caching.
        limit: Max orgs to match (0 = unlimited).

    Returns:
        Dict mapping org name -> match result dict.
    """
    unique_orgs = set()
    for row in rows:
        org = get_org_name(row)
        if org:
            unique_orgs.add(org)

    org_list = sorted(unique_orgs)
    if limit > 0:
        org_list = org_list[:limit]

    logger.info("Matching %d unique org names against OpenSanctions (%d entries)",
                len(org_list), len(entries))

    lookup = {}
    for i, org in enumerate(org_list):
        if i % 100 == 0:
            logger.info("[%d/%d] Matching orgs...", i, len(org_list))

        cache_key = f"os:{org.lower().strip()}"

        # Check cache
        if cache and use_cache:
            cached = cache.get(cache_key, max_age_days=CACHE_TTL_DAYS)
            if cached is not None:
                lookup[org] = cached
                continue

        # Fuzzy match
        result = fuzzy_match_org(org, entries)
        match_data = result if result else dict(EMPTY_RESULT)
        lookup[org] = match_data

        # Cache result
        if cache:
            cache.set(cache_key, match_data)

        if result:
            logger.info("  MATCH: '%s' -> %s (score=%s, %s)",
                        org[:50], result["os_entity_id"],
                        result["os_match_score"], result["os_dataset"])

    return lookup


# --- Main ---

def run(input_file: str, output_file: str, limit: int = 0,
        local_csv: str = "") -> int:
    """Run the OpenSanctions enrichment pipeline.

    Args:
        input_file: Input CSV path.
        output_file: Output CSV path.
        limit: Max orgs to match (0 = all).
        local_csv: Path to a local targets.simple.csv (skips download).

    Returns:
        Number of domains enriched with OpenSanctions data.
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
    cache_dir = os.path.dirname(CACHE_DB_PATH) or "."
    os.makedirs(cache_dir, exist_ok=True)
    cache = ShodanCache(db_path=CACHE_DB_PATH)

    try:
        # Load or download dataset
        if local_csv and os.path.isfile(local_csv):
            logger.info("Using local OpenSanctions CSV: %s", local_csv)
            with open(local_csv, "r", encoding="utf-8-sig", errors="replace") as f:
                entries = parse_opensanctions_csv(f)
        else:
            # Check if we need to re-download
            meta = cache.get("_dataset_meta", max_age_days=DATASET_TTL_DAYS)
            if meta and meta.get("entry_count", 0) > 0:
                logger.info("Dataset cache is fresh (%d entries). Re-parsing...",
                            meta["entry_count"])
                # Re-download anyway — we don't store the full dataset in SQLite,
                # just the match results. But the per-org cache should cover most orgs.
                entries = download_and_parse(cache_dir=cache_dir)
            else:
                entries = download_and_parse(cache_dir=cache_dir)

            if entries:
                cache.set("_dataset_meta", {"entry_count": len(entries)})

        if not entries:
            logger.warning("No OpenSanctions entries loaded — skipping enrichment")
            # Still write output with empty columns
            for col in OS_COLUMNS:
                if col not in fieldnames:
                    fieldnames.append(col)
            for row in rows:
                for col in OS_COLUMNS:
                    row.setdefault(col, "")
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            return 0

        # Build org lookup
        lookup = build_org_lookup(rows, entries, cache=cache, limit=limit)

        # Enrich rows
        enriched_count = 0
        for col in OS_COLUMNS:
            if col not in fieldnames:
                fieldnames.append(col)

        for row in rows:
            org = get_org_name(row)
            if org and org in lookup:
                os_data = lookup[org]
                for col in OS_COLUMNS:
                    row[col] = os_data.get(col, "")
                if os_data.get("os_match_score"):
                    enriched_count += 1
            else:
                for col in OS_COLUMNS:
                    row.setdefault(col, "")

        # Write output
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        logger.info("Enriched %d domains with OpenSanctions data. Output: %s",
                    enriched_count, output_file)
        return enriched_count
    finally:
        cache.close()


def main():
    parser = argparse.ArgumentParser(description="OpenSanctions Entity Screening")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Input CSV file")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output CSV file")
    parser.add_argument("--limit", type=int, default=0, help="Max orgs to match (0=all)")
    parser.add_argument("--local-csv", default="", help="Path to local targets.simple.csv (skip download)")
    args = parser.parse_args()

    count = run(args.input, args.output, args.limit, args.local_csv)
    logger.info("Done. %d domains enriched.", count)


if __name__ == "__main__":
    main()
