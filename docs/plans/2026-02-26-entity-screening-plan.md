# OpenSanctions & ICIJ Entity Screening — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build two enrichment scripts that fuzzy-match domain registrant orgs against global sanctions watchlists (OpenSanctions) and offshore leak databases (ICIJ OffshoreLeaks), feeding confidence modifiers into the fingerprint engine.

**Architecture:** Both scripts follow the `enrich_gleif.py` pattern: bulk dataset download → SQLite FTS5 lookup table → Levenshtein fuzzy match against `registrant_org`/`ssl_org` → append output columns. No per-domain API calls. Match scores stored as integer percentages (0-100) for compatibility with the fingerprint engine's `range` match_type.

**Tech Stack:** Python 3.10, requests, python-Levenshtein (already in requirements.txt), sqlite3 FTS5 (stdlib), ShodanCache from `scripts/shodan_utils.py`, `@retry` from `scripts/shared/retry.py`, pytest

**Design doc:** `docs/plans/2026-02-26-entity-screening-design.md`

---

### Task 1: OpenSanctions Enrichment Script + Tests (TDD)

**Files:**
- Create: `tests/test_opensanctions.py`
- Create: `scripts/enrich_opensanctions.py`

**Context:**
- OpenSanctions `targets.simple.csv` has columns: `id`, `schema`, `name`, `aliases` (`;`-delimited), `dataset` (`;`-delimited), plus others we don't need
- ~1.29M rows, ~459 MB download
- A local copy exists at `targets.simple.csv` in the repo root (for development/testing; not committed)
- `ShodanCache` in `scripts/shodan_utils.py` has `get(key, max_age_days)`, `set(key, data)`, `close()`
- `@retry` in `scripts/shared/retry.py` wraps functions with exponential backoff
- `get_org_name()` pattern from `enrich_gleif.py`: prefers `registrant_org`, falls back to `ssl_org`

**Step 1: Write `tests/test_opensanctions.py`**

```python
#!/usr/bin/env python3
"""Tests for the OpenSanctions entity screening enrichment module."""

import os
import sys
import csv
import io
import tempfile

import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from enrich_opensanctions import (
    parse_opensanctions_csv,
    fuzzy_match_org,
    get_org_name,
    build_org_lookup,
    MATCH_THRESHOLD,
)


# --- Sample CSV data (minimal) ---

SAMPLE_CSV = """\
"id","schema","name","aliases","birth_date","countries","addresses","identifiers","sanctions","phones","emails","program_ids","dataset","first_seen","last_seen","last_change"
"NK-001","Company","Apple Inc.","Apple Computer;Apple Incorporated","","us","","","","","","","US OFAC SDN List","2024-01-01","2025-01-01","2025-01-01"
"NK-002","Person","Vladimir Putin","Владимир Путин;V. Putin","1952-10-07","ru","","","","","","","EU Consolidated Sanctions","2024-01-01","2025-01-01","2025-01-01"
"NK-003","Company","Acme Holdings Ltd","","","pa","","","","","","","Panama Sanctions","2024-01-01","2025-01-01","2025-01-01"
"""


# ============================================================
# CSV Parsing + FTS Loading (2 tests)
# ============================================================

class TestParseOpenSanctionsCsv:

    def test_loads_names_and_aliases(self):
        """Parsing should produce entries for primary names AND aliases."""
        entries = parse_opensanctions_csv(io.StringIO(SAMPLE_CSV))
        names = [e["name"] for e in entries]
        # Primary names
        assert "apple inc." in names
        assert "vladimir putin" in names
        # Aliases expanded
        assert "apple computer" in names
        assert "apple incorporated" in names
        assert "v. putin" in names

    def test_preserves_metadata(self):
        """Each entry should carry entity_id, entity_type, dataset."""
        entries = parse_opensanctions_csv(io.StringIO(SAMPLE_CSV))
        apple_entries = [e for e in entries if e["entity_id"] == "NK-001"]
        assert len(apple_entries) >= 1
        assert apple_entries[0]["entity_type"] == "Company"
        assert apple_entries[0]["dataset"] == "US OFAC SDN List"


# ============================================================
# Fuzzy Matching (3 tests)
# ============================================================

class TestFuzzyMatchOrg:

    def test_exact_match_returns_100(self):
        """Exact name match should return score 100."""
        entries = parse_opensanctions_csv(io.StringIO(SAMPLE_CSV))
        result = fuzzy_match_org("Apple Inc.", entries)
        assert result is not None
        assert result["os_match_score"] == 100
        assert result["os_entity_id"] == "NK-001"

    def test_close_match_above_threshold(self):
        """A close-enough name should match above threshold."""
        entries = parse_opensanctions_csv(io.StringIO(SAMPLE_CSV))
        result = fuzzy_match_org("Acme Holdings", entries)
        assert result is not None
        assert result["os_match_score"] >= MATCH_THRESHOLD

    def test_no_match_below_threshold(self):
        """A completely unrelated name should return None."""
        entries = parse_opensanctions_csv(io.StringIO(SAMPLE_CSV))
        result = fuzzy_match_org("Totally Random Corp XYZ", entries)
        assert result is None


# ============================================================
# Org Name Extraction (2 tests)
# ============================================================

class TestGetOrgName:

    def test_prefers_registrant_org(self):
        row = {"registrant_org": "Apple Inc.", "ssl_org": "Cloudflare"}
        assert get_org_name(row) == "Apple Inc."

    def test_falls_back_to_ssl_org(self):
        row = {"registrant_org": "", "ssl_org": "Google LLC"}
        assert get_org_name(row) == "Google LLC"


# ============================================================
# Cache Behavior (2 tests)
# ============================================================

class TestCacheBehavior:

    def test_cache_miss_triggers_match(self):
        """When cache has no entry, build_org_lookup should perform matching."""
        entries = parse_opensanctions_csv(io.StringIO(SAMPLE_CSV))
        mock_cache = MagicMock()
        mock_cache.get.return_value = None

        rows = [{"registrant_org": "Apple Inc.", "ssl_org": ""}]
        lookup = build_org_lookup(rows, entries, cache=mock_cache, use_cache=True)

        mock_cache.set.assert_called()
        assert "Apple Inc." in lookup

    def test_cache_hit_skips_match(self):
        """When cache has a fresh entry, build_org_lookup should skip matching."""
        cached = {
            "os_match_score": 100, "os_entity_type": "Company",
            "os_dataset": "Cached", "os_entity_id": "NK-CACHED",
        }
        mock_cache = MagicMock()
        mock_cache.get.return_value = cached

        entries = []  # empty — shouldn't be used
        rows = [{"registrant_org": "Apple Inc.", "ssl_org": ""}]
        lookup = build_org_lookup(rows, entries, cache=mock_cache, use_cache=True)

        assert lookup["Apple Inc."]["os_entity_id"] == "NK-CACHED"


# ============================================================
# Dataset Download (1 test)
# ============================================================

class TestDatasetDownload:

    def test_download_populates_entries(self):
        """Mock download should produce parsed entries."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.iter_lines.return_value = [
            line.encode("utf-8") for line in SAMPLE_CSV.strip().split("\n")
        ]
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("enrich_opensanctions.requests.get", return_value=mock_resp):
            from enrich_opensanctions import download_and_parse
            entries = download_and_parse(cache_dir="/tmp/test_os_cache")

        assert len(entries) > 0
        names = [e["name"] for e in entries]
        assert "apple inc." in names
```

**Step 2: Write `scripts/enrich_opensanctions.py`**

```python
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
```

**Step 3: Run tests**

Run: `pytest tests/test_opensanctions.py -v`
Expected: 10 passed

**Step 4: Run full test suite**

Run: `pytest tests/ -q`
Expected: All tests pass (164 existing + 10 new)

**Step 5: Commit**

```bash
git add scripts/enrich_opensanctions.py tests/test_opensanctions.py
git commit -m "feat: add OpenSanctions entity screening enrichment with tests"
```

---

### Task 2: ICIJ OffshoreLeaks Enrichment Script + Tests (TDD)

**Files:**
- Create: `tests/test_icij.py`
- Create: `scripts/enrich_icij.py`

**Context:**
- ICIJ bulk ZIP from `https://offshoreleaks-data.icij.org/offshoreleaks/csv/full-oldb.LATEST.zip`
- Contains a `nodes-entities.csv` and `nodes-officers.csv` (plus others we skip)
- Column names in the CSVs may vary — the script should discover them by reading headers
- Key columns expected: `node_id` (or `id`), `name`, `jurisdiction`, `sourceID` (dataset name)
- We load entities + officers, skip intermediaries/addresses
- Same Levenshtein matching pattern as OpenSanctions
- Cache: `data/.icij_cache/cache.db`, TTL 7 days

**IMPORTANT NOTE:** The exact CSV file names and column headers inside the ICIJ ZIP may differ from what's documented. The implementer MUST:
1. Download the ZIP (or use a cached copy)
2. List all files inside
3. Identify which CSVs contain entity and officer data
4. Read headers and adapt the column name constants accordingly

The test file uses mock data with assumed column names. If the real column names differ, update both the test mock data and the script constants.

**Step 1: Write `tests/test_icij.py`**

```python
#!/usr/bin/env python3
"""Tests for the ICIJ OffshoreLeaks entity screening enrichment module."""

import os
import sys
import csv
import io
import zipfile
import tempfile

import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from enrich_icij import (
    parse_icij_nodes_csv,
    extract_icij_csvs,
    fuzzy_match_org,
    get_org_name,
    build_org_lookup,
    MATCH_THRESHOLD,
)


# --- Sample CSV data (mimics ICIJ nodes format) ---
# NOTE: Column names may need adjustment after inspecting the real ZIP.

SAMPLE_ENTITIES_CSV = """\
node_id,name,jurisdiction,sourceID,note
10000001,Acme Offshore Holdings,Panama,Panama Papers,
10000002,Shell Corp International Ltd,British Virgin Islands,Paradise Papers,
10000003,Golden Dragon Enterprises,Hong Kong,Pandora Papers,
"""

SAMPLE_OFFICERS_CSV = """\
node_id,name,jurisdiction,sourceID,note
20000001,John Doe,Panama,Panama Papers,Director
20000002,Jane Smith,United Kingdom,Paradise Papers,Shareholder
"""


# ============================================================
# ZIP Extraction (1 test)
# ============================================================

class TestExtractIcijCsvs:

    def test_extracts_entity_and_officer_csvs(self):
        """Should extract entity and officer CSV content from a mock ZIP."""
        # Build a mock ZIP in memory
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("nodes-entities.csv", SAMPLE_ENTITIES_CSV)
            zf.writestr("nodes-officers.csv", SAMPLE_OFFICERS_CSV)
            zf.writestr("nodes-addresses.csv", "we skip this")
        buf.seek(0)

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(buf.read())
            tmp_path = tmp.name

        try:
            entity_data, officer_data = extract_icij_csvs(tmp_path)
            assert entity_data is not None
            assert officer_data is not None
        finally:
            os.unlink(tmp_path)


# ============================================================
# CSV Parsing + FTS Loading (2 tests)
# ============================================================

class TestParseIcijNodesCsv:

    def test_loads_entity_names(self):
        """Parsing entities CSV should produce name entries."""
        entries = parse_icij_nodes_csv(
            io.StringIO(SAMPLE_ENTITIES_CSV), node_type="Entity"
        )
        names = [e["name"] for e in entries]
        assert "acme offshore holdings" in names
        assert "shell corp international ltd" in names

    def test_loads_officers_with_metadata(self):
        """Parsing officers CSV should preserve jurisdiction and dataset."""
        entries = parse_icij_nodes_csv(
            io.StringIO(SAMPLE_OFFICERS_CSV), node_type="Officer"
        )
        john = [e for e in entries if "john doe" in e["name"]]
        assert len(john) == 1
        assert john[0]["jurisdiction"] == "Panama"
        assert john[0]["dataset"] == "Panama Papers"


# ============================================================
# Fuzzy Matching (3 tests)
# ============================================================

class TestFuzzyMatchOrg:

    def test_exact_match_returns_100(self):
        entries = parse_icij_nodes_csv(
            io.StringIO(SAMPLE_ENTITIES_CSV), node_type="Entity"
        )
        result = fuzzy_match_org("Acme Offshore Holdings", entries)
        assert result is not None
        assert result["icij_match_score"] == 100
        assert result["icij_entity_match"] == "True"

    def test_close_match_above_threshold(self):
        entries = parse_icij_nodes_csv(
            io.StringIO(SAMPLE_ENTITIES_CSV), node_type="Entity"
        )
        result = fuzzy_match_org("Acme Offshore Holding", entries)
        assert result is not None
        assert result["icij_match_score"] >= MATCH_THRESHOLD

    def test_no_match_below_threshold(self):
        entries = parse_icij_nodes_csv(
            io.StringIO(SAMPLE_ENTITIES_CSV), node_type="Entity"
        )
        result = fuzzy_match_org("Completely Random Corp XYZ 999", entries)
        assert result is None


# ============================================================
# Cache Behavior (2 tests)
# ============================================================

class TestCacheBehavior:

    def test_cache_miss_triggers_match(self):
        entries = parse_icij_nodes_csv(
            io.StringIO(SAMPLE_ENTITIES_CSV), node_type="Entity"
        )
        mock_cache = MagicMock()
        mock_cache.get.return_value = None

        rows = [{"registrant_org": "Acme Offshore Holdings", "ssl_org": ""}]
        lookup = build_org_lookup(rows, entries, cache=mock_cache, use_cache=True)

        mock_cache.set.assert_called()
        assert "Acme Offshore Holdings" in lookup

    def test_cache_hit_skips_match(self):
        cached = {
            "icij_match_score": 95, "icij_entity_match": "True",
            "icij_dataset": "Cached", "icij_jurisdiction": "BVI",
        }
        mock_cache = MagicMock()
        mock_cache.get.return_value = cached

        rows = [{"registrant_org": "Cached Corp", "ssl_org": ""}]
        lookup = build_org_lookup(rows, [], cache=mock_cache, use_cache=True)

        assert lookup["Cached Corp"]["icij_jurisdiction"] == "BVI"
```

**Step 2: Write `scripts/enrich_icij.py`**

```python
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
```

**Step 3: Run tests**

Run: `pytest tests/test_icij.py -v`
Expected: 8 passed

**Step 4: Run full test suite**

Run: `pytest tests/ -q`
Expected: All tests pass

**Step 5: Commit**

```bash
git add scripts/enrich_icij.py tests/test_icij.py
git commit -m "feat: add ICIJ OffshoreLeaks entity screening enrichment with tests"
```

---

### Task 3: Update Fingerprint YAMLs with Entity Screening Modifiers

**Files:**
- Modify: `config/fingerprints/FP-0001-ovh-cpanel-dea.yaml`
- Modify: `config/fingerprints/FP-0002-alibaba-sideloading.yaml`
- Modify: `config/fingerprints/FP-0003-crypto-finance-cohosting.yaml`
- Modify: `config/fingerprints/FP-0004-gname-cloudflare-china.yaml`
- Modify: `config/fingerprints/FP-0005-godaddy-bulk-registration.yaml`
- Modify: `config/fingerprints/FP-0006-shell-domain-mx-cluster.yaml`
- Modify: `config/fingerprints/FP-0007-typosquat-evasion-infra.yaml`

**Step 1: Add entity screening modifiers to all 7 fingerprints**

Append these two modifiers to the `confidence_modifiers` section of EACH YAML file:

```yaml
  - field: os_match_score
    match_type: range
    value: "70-100"
    delta: 20
  - field: icij_entity_match
    match_type: exact
    value: "True"
    delta: 15
```

**Step 2: Verify all fingerprints still load**

Run: `python -c "import sys; sys.path.insert(0,'scripts'); from match_fingerprints import load_fingerprints; fps=load_fingerprints(); print(f'{len(fps)} loaded'); [print(f'  {fp[\"id\"]}: {len(fp.get(\"confidence_modifiers\",[]))} modifiers') for fp in fps]"`

Expected: 7 loaded, each with 2 more modifiers than before (e.g., FP-0001 had 4, now has 6).

**Step 3: Write modifier tests**

Add these tests to `tests/test_opensanctions.py`:

```python
# Add at the end of the file

class TestFingerPrintModifiers:

    def test_opensanctions_score_applies_delta(self):
        """os_match_score in range 70-100 should apply +20 delta."""
        from match_fingerprints import calculate_confidence, validate_fingerprint

        fp = {
            "id": "FP-TEST", "name": "Test", "description": "", "version": 1,
            "indicators": [{"field": "asn", "match_type": "exact", "value": "16276", "required": True}],
            "confidence_base": 60,
            "confidence_modifiers": [
                {"field": "os_match_score", "match_type": "range", "value": "70-100", "delta": 20},
            ],
            "flame_tp_ids": [], "ttl_days": 30,
        }
        fp = validate_fingerprint(fp, source="test")
        row = {"asn": "16276", "os_match_score": "85"}
        assert calculate_confidence(fp, row) == 80
```

Add this test to `tests/test_icij.py`:

```python
# Add at the end of the file

class TestFingerprintModifiers:

    def test_icij_match_applies_delta(self):
        """icij_entity_match == 'True' should apply +15 delta."""
        from match_fingerprints import calculate_confidence, validate_fingerprint

        fp = {
            "id": "FP-TEST", "name": "Test", "description": "", "version": 1,
            "indicators": [{"field": "asn", "match_type": "exact", "value": "16276", "required": True}],
            "confidence_base": 60,
            "confidence_modifiers": [
                {"field": "icij_entity_match", "match_type": "exact", "value": "True", "delta": 15},
            ],
            "flame_tp_ids": [], "ttl_days": 30,
        }
        fp = validate_fingerprint(fp, source="test")
        row = {"asn": "16276", "icij_entity_match": "True"}
        assert calculate_confidence(fp, row) == 75
```

**Step 4: Run tests**

Run: `pytest tests/test_fingerprints.py tests/test_opensanctions.py tests/test_icij.py -v`
Expected: All pass

**Step 5: Commit**

```bash
git add config/fingerprints/ tests/test_opensanctions.py tests/test_icij.py
git commit -m "feat: add OpenSanctions and ICIJ confidence modifiers to all 7 fingerprints"
```

---

### Task 4: Pipeline Integration + gitignore

**Files:**
- Modify: `.github/workflows/update_intelligence.yml`
- Modify: `.gitignore`

**Step 1: Add both workflow steps**

Insert after the "GLEIF Entity Verification" step and before "Infrastructure Fingerprinting":

```yaml
      - name: OpenSanctions Entity Screening
        timeout-minutes: 30
        continue-on-error: true
        run: python scripts/enrich_opensanctions.py

      - name: ICIJ OffshoreLeaks Screening
        timeout-minutes: 30
        continue-on-error: true
        run: python scripts/enrich_icij.py
```

**Step 2: Add cache directories to `.gitignore`**

Append:
```
data/.opensanctions_cache/
data/.icij_cache/
```

**Step 3: Verify workflow YAML is valid**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/update_intelligence.yml')); print('Valid YAML')"`
Expected: `Valid YAML`

**Step 4: Commit**

```bash
git add .github/workflows/update_intelligence.yml .gitignore
git commit -m "ci: add OpenSanctions and ICIJ screening steps to pipeline workflow"
```

---

### Task 5: End-to-End Validation

**Step 1: Run OpenSanctions against synthetic data using local CSV**

```bash
echo "domain,registrant_org,ssl_org,asn,nameservers" > /tmp/test_os_input.csv
echo "suspect.com,Myanmar Yatai International Holding Group Co. LTD,,16276,ns1.example.com" >> /tmp/test_os_input.csv
echo "clean.com,Apple Inc.,,15169,ns1.apple.com" >> /tmp/test_os_input.csv
echo "unknown.com,,,,ns1.example.com" >> /tmp/test_os_input.csv
python scripts/enrich_opensanctions.py --input /tmp/test_os_input.csv --output /tmp/test_os_output.csv --limit 3 --local-csv targets.simple.csv
head -5 /tmp/test_os_output.csv
```

Expected: `suspect.com` should have a high `os_match_score` (sanctioned entity). `clean.com` may or may not match (Apple Inc. is not sanctioned — could get a false match against a similarly-named entity). `unknown.com` should have empty columns.

**Step 2: Run full test suite**

Run: `pytest tests/ -q`
Expected: All tests pass

**Step 3: Commit any final adjustments**

```bash
git add -A
git commit -m "test: validate entity screening end-to-end"
```
