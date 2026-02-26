#!/usr/bin/env python3
"""
enrich_icij.py

ICIJ OffshoreLeaks Entity Screening.
Downloads the ICIJ bulk dataset ZIP, extracts entity and officer CSVs,
and fuzzy-matches domain registrant organizations against offshore
leak entities using Levenshtein distance.

Output columns: icij_match_score, icij_entity_match, icij_dataset, icij_jurisdiction
"""

import argparse
import csv
import io
import logging
import os
import sys
import tempfile
import zipfile
from typing import Any, Dict, List, Optional, Tuple

import requests
from Levenshtein import ratio as levenshtein_ratio

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from shodan_utils import ShodanCache
from shared.retry import retry

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Configuration ---

ICIJ_ZIP_URL = "https://offshoreleaks-data.icij.org/offshoreleaks/csv/full-oldb.LATEST.zip"
DEFAULT_INPUT = "data/dea_domains_probed.csv"
DEFAULT_OUTPUT = "data/dea_domains_probed.csv"
CACHE_DB_PATH = "data/.icij_cache/cache.db"
DATASET_TTL_DAYS = 7   # re-download dataset weekly
CACHE_TTL_DAYS = 7     # per-org match cache TTL
MATCH_THRESHOLD = 70   # minimum Levenshtein score (0-100)

# CSV file name patterns inside the ZIP (ICIJ uses these prefixes)
ENTITY_CSV_PATTERNS = ["nodes-entities", "nodes_entities", "entities"]
OFFICER_CSV_PATTERNS = ["nodes-officers", "nodes_officers", "officers"]

# Column name mappings — the script tries these in order
ID_COLUMNS = ["node_id", "id", "n.node_id"]
NAME_COLUMNS = ["name", "n.name"]
JURISDICTION_COLUMNS = ["jurisdiction", "jurisdiction_description", "n.jurisdiction"]
DATASET_COLUMNS = ["sourceID", "source_id", "n.sourceID"]

ICIJ_COLUMNS = ["icij_match_score", "icij_entity_match", "icij_dataset", "icij_jurisdiction"]

EMPTY_RESULT = {
    "icij_match_score": "",
    "icij_entity_match": "",
    "icij_dataset": "",
    "icij_jurisdiction": "",
}


# --- Helpers ---

def _find_column(fieldnames: List[str], candidates: List[str]) -> str:
    """Find the first matching column name from a list of candidates."""
    for c in candidates:
        if c in fieldnames:
            return c
    return ""


def get_org_name(row: Dict[str, str]) -> str:
    """Extract the best org name from a domain row."""
    org = row.get("registrant_org", "").strip()
    if org:
        return org
    return row.get("ssl_org", "").strip()


# --- Core Functions ---

def extract_icij_csvs(
    zip_path: str,
) -> Tuple[Optional[str], Optional[str]]:
    """Extract entity and officer CSV content from an ICIJ ZIP file.

    Searches for files matching known entity/officer patterns.

    Args:
        zip_path: Path to the downloaded ZIP file.

    Returns:
        Tuple of (entity_csv_content, officer_csv_content) as strings.
        Either may be None if not found.
    """
    entity_data = None
    officer_data = None

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        logger.info("ZIP contains %d files: %s", len(names),
                    ", ".join(n for n in names[:10]))

        for name in names:
            name_lower = name.lower()
            basename = os.path.basename(name_lower)

            if entity_data is None:
                for pattern in ENTITY_CSV_PATTERNS:
                    if pattern in basename and basename.endswith(".csv"):
                        logger.info("Found entity CSV: %s", name)
                        entity_data = zf.read(name).decode("utf-8-sig", errors="replace")
                        break

            if officer_data is None:
                for pattern in OFFICER_CSV_PATTERNS:
                    if pattern in basename and basename.endswith(".csv"):
                        logger.info("Found officer CSV: %s", name)
                        officer_data = zf.read(name).decode("utf-8-sig", errors="replace")
                        break

    if entity_data is None:
        logger.warning("No entity CSV found in ZIP")
    if officer_data is None:
        logger.warning("No officer CSV found in ZIP")

    return entity_data, officer_data


def parse_icij_nodes_csv(
    file_obj,
    node_type: str = "Entity",
) -> List[Dict[str, str]]:
    """Parse an ICIJ nodes CSV into a list of name entries.

    Handles variable column names by trying known alternatives.

    Args:
        file_obj: File-like object with CSV data.
        node_type: "Entity" or "Officer" (for metadata tagging).

    Returns:
        List of dicts with keys: name, entity_id, entity_type, dataset, jurisdiction.
    """
    entries = []
    reader = csv.DictReader(file_obj)
    fieldnames = reader.fieldnames or []

    id_col = _find_column(fieldnames, ID_COLUMNS)
    name_col = _find_column(fieldnames, NAME_COLUMNS)
    jurisdiction_col = _find_column(fieldnames, JURISDICTION_COLUMNS)
    dataset_col = _find_column(fieldnames, DATASET_COLUMNS)

    if not name_col:
        logger.error("No name column found in ICIJ CSV (tried: %s). Headers: %s",
                      NAME_COLUMNS, fieldnames)
        return []

    for row in reader:
        name = row.get(name_col, "").strip()
        if not name:
            continue

        entries.append({
            "name": name.lower(),
            "entity_id": row.get(id_col, "") if id_col else "",
            "entity_type": node_type,
            "dataset": row.get(dataset_col, "") if dataset_col else "",
            "jurisdiction": row.get(jurisdiction_col, "") if jurisdiction_col else "",
        })

    logger.info("Parsed %d %s entries from ICIJ CSV", len(entries), node_type)
    return entries


@retry(max_attempts=3, backoff_base=2.0, exceptions=(requests.RequestException,))
def _download_zip(url: str) -> requests.Response:
    """Download the ICIJ ZIP with retry."""
    return requests.get(url, stream=True, timeout=180)


def download_and_parse(
    url: str = ICIJ_ZIP_URL,
    cache_dir: str = "",
) -> List[Dict[str, str]]:
    """Download ICIJ ZIP, extract, and parse entity + officer CSVs.

    Args:
        url: URL to download from.
        cache_dir: Directory for temp file storage.

    Returns:
        Combined list of entity + officer entries.
    """
    logger.info("Downloading ICIJ OffshoreLeaks dataset from %s", url)

    resp = _download_zip(url)
    if resp.status_code != 200:
        logger.error("Download failed with status %d", resp.status_code)
        return []

    tmp_dir = cache_dir or tempfile.gettempdir()
    os.makedirs(tmp_dir, exist_ok=True)
    zip_path = os.path.join(tmp_dir, "full-oldb.zip")

    try:
        with open(zip_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)

        logger.info("Downloaded to %s, extracting...", zip_path)

        entity_data, officer_data = extract_icij_csvs(zip_path)

        entries = []
        if entity_data:
            entries.extend(parse_icij_nodes_csv(io.StringIO(entity_data), "Entity"))
        if officer_data:
            entries.extend(parse_icij_nodes_csv(io.StringIO(officer_data), "Officer"))

        return entries
    finally:
        if os.path.exists(zip_path):
            try:
                os.remove(zip_path)
            except OSError:
                pass


def fuzzy_match_org(
    org_name: str,
    entries: List[Dict[str, str]],
) -> Optional[Dict[str, str]]:
    """Fuzzy-match an org name against ICIJ entries.

    Args:
        org_name: The organization name to match.
        entries: Parsed ICIJ entries.

    Returns:
        Dict with icij_match_score, icij_entity_match, icij_dataset,
        icij_jurisdiction, or None if no match above threshold.
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

        if score == 100:
            break

    if best_score >= MATCH_THRESHOLD and best_entry is not None:
        return {
            "icij_match_score": str(best_score),
            "icij_entity_match": "True",
            "icij_dataset": best_entry.get("dataset", ""),
            "icij_jurisdiction": best_entry.get("jurisdiction", ""),
        }

    return None


def build_org_lookup(
    rows: List[Dict[str, str]],
    entries: List[Dict[str, str]],
    cache: Optional[Any] = None,
    use_cache: bool = True,
    limit: int = 0,
) -> Dict[str, Dict[str, str]]:
    """Build lookup table of org_name -> ICIJ match result."""
    unique_orgs = set()
    for row in rows:
        org = get_org_name(row)
        if org:
            unique_orgs.add(org)

    org_list = sorted(unique_orgs)
    if limit > 0:
        org_list = org_list[:limit]

    logger.info("Matching %d unique org names against ICIJ (%d entries)",
                len(org_list), len(entries))

    lookup = {}
    for i, org in enumerate(org_list):
        if i % 100 == 0:
            logger.info("[%d/%d] Matching orgs...", i, len(org_list))

        cache_key = f"icij:{org.lower().strip()}"

        if cache and use_cache:
            cached = cache.get(cache_key, max_age_days=CACHE_TTL_DAYS)
            if cached is not None:
                lookup[org] = cached
                continue

        result = fuzzy_match_org(org, entries)
        match_data = result if result else dict(EMPTY_RESULT)
        lookup[org] = match_data

        if cache:
            cache.set(cache_key, match_data)

        if result:
            logger.info("  MATCH: '%s' -> %s (score=%s, %s)",
                        org[:50], result["icij_dataset"],
                        result["icij_match_score"], result["icij_jurisdiction"])

    return lookup


# --- Main ---

def run(input_file: str, output_file: str, limit: int = 0) -> int:
    """Run the ICIJ OffshoreLeaks enrichment pipeline."""
    if not os.path.isfile(input_file):
        logger.error("Input file not found: %s", input_file)
        return 0

    with open(input_file, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames) if reader.fieldnames else []
        rows = list(reader)

    if not rows:
        logger.warning("No rows in input file")
        return 0

    cache_dir = os.path.dirname(CACHE_DB_PATH) or "."
    os.makedirs(cache_dir, exist_ok=True)
    cache = ShodanCache(db_path=CACHE_DB_PATH)

    try:
        meta = cache.get("_dataset_meta", max_age_days=DATASET_TTL_DAYS)
        if meta and meta.get("entry_count", 0) > 0:
            logger.info("Dataset cache is fresh (%d entries)", meta["entry_count"])

        entries = download_and_parse(cache_dir=cache_dir)

        if entries:
            cache.set("_dataset_meta", {"entry_count": len(entries)})

        if not entries:
            logger.warning("No ICIJ entries loaded — skipping enrichment")
            for col in ICIJ_COLUMNS:
                if col not in fieldnames:
                    fieldnames.append(col)
            for row in rows:
                for col in ICIJ_COLUMNS:
                    row.setdefault(col, "")
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            return 0

        lookup = build_org_lookup(rows, entries, cache=cache, limit=limit)

        enriched_count = 0
        for col in ICIJ_COLUMNS:
            if col not in fieldnames:
                fieldnames.append(col)

        for row in rows:
            org = get_org_name(row)
            if org and org in lookup:
                icij_data = lookup[org]
                for col in ICIJ_COLUMNS:
                    row[col] = icij_data.get(col, "")
                if icij_data.get("icij_entity_match") == "True":
                    enriched_count += 1
            else:
                for col in ICIJ_COLUMNS:
                    row.setdefault(col, "")

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        logger.info("Enriched %d domains with ICIJ data. Output: %s",
                    enriched_count, output_file)
        return enriched_count
    finally:
        cache.close()


def main():
    parser = argparse.ArgumentParser(description="ICIJ OffshoreLeaks Entity Screening")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Input CSV file")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output CSV file")
    parser.add_argument("--limit", type=int, default=0, help="Max orgs to match (0=all)")
    args = parser.parse_args()

    count = run(args.input, args.output, args.limit)
    logger.info("Done. %d domains enriched.", count)


if __name__ == "__main__":
    main()
