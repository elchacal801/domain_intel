# GLEIF Entity Legitimacy Verification — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a GLEIF API enrichment module that verifies domain registrant legitimacy and feeds confidence modifiers into the fingerprint engine.

**Architecture:** Standalone `scripts/enrich_gleif.py` reads org names from enriched domain CSV (prefers `registrant_org`, falls back to `ssl_org`), deduplicates, queries GLEIF REST API with 7-day SQLite cache and 0.5s rate limiting, appends 5 new columns. Fingerprint YAML files get GLEIF-based confidence modifiers.

**Tech Stack:** Python 3.10, requests, PyYAML, sqlite3 (via existing ShodanCache), pytest, shared/retry.py

**Design doc:** `docs/plans/2026-02-25-gleif-enrichment-design.md`

---

### Task 1: RDAP Registrant Extraction

**Files:**
- Modify: `scripts/enrich_reputation.py:86-118` (extend `get_rdap_age`)
- Modify: `scripts/enrich_reputation.py:120-145` (add field to `process_one`)
- Modify: `scripts/enrich_reputation.py:166` (add to `new_cols`)

**Step 1: Extend `get_rdap_age()` to extract registrant org**

In `scripts/enrich_reputation.py`, rename `get_rdap_age` to `get_rdap_data` and expand it to also extract the registrant organization name from the RDAP response. The function currently returns `{"creation_date": ..., "age_days": ...}`. Add `"registrant_org": ""` to the result dict.

After the existing events-parsing block (around line 114), add registrant extraction:

```python
            # Extract registrant organization
            for entity in data.get("entities", []):
                if "registrant" in entity.get("roles", []):
                    vcard_array = entity.get("vcardArray", [[], []])
                    if len(vcard_array) > 1:
                        for vcard in vcard_array[1]:
                            if isinstance(vcard, list) and len(vcard) > 3 and vcard[0] in ("fn", "org"):
                                org_val = vcard[3]
                                if isinstance(org_val, str) and org_val.strip():
                                    res["registrant_org"] = sanitize_csv_value(org_val.strip())
                                break
                    break
```

**Step 2: Update `process_one()` to pass through the new field**

At line 137, add:
```python
    row["registrant_org"] = rdap.get("registrant_org", "")
```

**Step 3: Add `registrant_org` to `new_cols` list**

At line 166, change:
```python
    new_cols = ["rbl_hits", "creation_date", "age_days", "otx_risk", "registrant_org"]
```

**Step 4: Verify syntax**

Run: `python -m py_compile scripts/enrich_reputation.py`
Expected: No output (success)

**Step 5: Commit**

```bash
git add scripts/enrich_reputation.py
git commit -m "feat: extract registrant_org from RDAP response in enrich_reputation.py"
```

---

### Task 2: Core GLEIF Enrichment Script + Tests (TDD)

**Files:**
- Create: `tests/test_gleif.py`
- Create: `scripts/enrich_gleif.py`

This is the main task. Write tests first, then implement.

**Step 1: Write `tests/test_gleif.py` with 11+ test functions**

```python
#!/usr/bin/env python3
"""Tests for the GLEIF entity verification enrichment module."""

import os
import sys
import json
import time
import tempfile

import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from enrich_gleif import (
    parse_gleif_response,
    get_org_name,
    query_gleif,
    build_org_lookup,
)


# --- Mock GLEIF API Responses ---

ACTIVE_LEI_RESPONSE = {
    "data": [
        {
            "id": "7ZW8QJWVPR4P1J1KQKYI",
            "type": "lei-records",
            "attributes": {
                "lei": "7ZW8QJWVPR4P1J1KQKYI",
                "entity": {
                    "legalName": {"name": "Apple Inc."},
                    "status": "ACTIVE",
                    "jurisdiction": "US-CA",
                    "registeredAt": {"id": "RA000598"},
                },
                "registration": {
                    "status": "ISSUED",
                },
            },
            "relationships": {
                "direct-parent": {
                    "links": {"related": "https://api.gleif.org/api/v1/lei-records/7ZW8QJWVPR4P1J1KQKYI/direct-parent"}
                }
            },
        }
    ],
    "meta": {"pagination": {"total": 1}},
}

LAPSED_LEI_RESPONSE = {
    "data": [
        {
            "id": "XYZLAPSED123456ABCD",
            "type": "lei-records",
            "attributes": {
                "lei": "XYZLAPSED123456ABCD",
                "entity": {
                    "legalName": {"name": "Defunct Corp Ltd"},
                    "status": "LAPSED",
                    "jurisdiction": "GB",
                },
                "registration": {"status": "LAPSED"},
            },
            "relationships": {},
        }
    ],
    "meta": {"pagination": {"total": 1}},
}

EMPTY_RESPONSE = {
    "data": [],
    "meta": {"pagination": {"total": 0}},
}


# ============================================================
# API Response Parsing (3 tests)
# ============================================================

class TestParseGleifResponse:

    def test_active_lei_parsed(self):
        result = parse_gleif_response(ACTIVE_LEI_RESPONSE)
        assert result["gleif_lei"] == "7ZW8QJWVPR4P1J1KQKYI"
        assert result["gleif_status"] == "ACTIVE"
        assert result["gleif_legal_name"] == "Apple Inc."
        assert result["gleif_jurisdiction"] == "US-CA"
        assert result["gleif_has_parent"] == "True"

    def test_lapsed_lei_parsed(self):
        result = parse_gleif_response(LAPSED_LEI_RESPONSE)
        assert result["gleif_lei"] == "XYZLAPSED123456ABCD"
        assert result["gleif_status"] == "LAPSED"
        assert result["gleif_legal_name"] == "Defunct Corp Ltd"
        assert result["gleif_has_parent"] == "False"

    def test_no_results_returns_empty(self):
        result = parse_gleif_response(EMPTY_RESPONSE)
        assert result["gleif_lei"] == ""
        assert result["gleif_status"] == ""
        assert result["gleif_legal_name"] == ""
        assert result["gleif_jurisdiction"] == ""
        assert result["gleif_has_parent"] == ""


# ============================================================
# Org Name Extraction (2 tests)
# ============================================================

class TestGetOrgName:

    def test_prefers_registrant_org(self):
        row = {"registrant_org": "Apple Inc.", "ssl_org": "Cloudflare Inc."}
        assert get_org_name(row) == "Apple Inc."

    def test_falls_back_to_ssl_org(self):
        row = {"registrant_org": "", "ssl_org": "Google LLC"}
        assert get_org_name(row) == "Google LLC"

    def test_returns_empty_when_both_missing(self):
        row = {"registrant_org": "", "ssl_org": ""}
        assert get_org_name(row) == ""


# ============================================================
# Cache Behavior (3 tests)
# ============================================================

class TestCacheBehavior:

    def test_cache_miss_triggers_api_call(self):
        """When cache has no entry, query_gleif should call the API."""
        mock_cache = MagicMock()
        mock_cache.get.return_value = None  # cache miss

        with patch("enrich_gleif.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = ACTIVE_LEI_RESPONSE
            mock_get.return_value = mock_resp

            result = query_gleif("Apple Inc.", cache=mock_cache, rate_delay=0)

            mock_get.assert_called()  # API was hit
            mock_cache.set.assert_called_once()  # result was cached
            assert result["gleif_lei"] == "7ZW8QJWVPR4P1J1KQKYI"

    def test_cache_hit_skips_api_call(self):
        """When cache has a fresh entry, query_gleif should NOT call the API."""
        cached_data = {
            "gleif_lei": "CACHED123",
            "gleif_status": "ACTIVE",
            "gleif_legal_name": "Cached Corp",
            "gleif_jurisdiction": "US",
            "gleif_has_parent": "False",
        }
        mock_cache = MagicMock()
        mock_cache.get.return_value = cached_data

        with patch("enrich_gleif.requests.get") as mock_get:
            result = query_gleif("Cached Corp", cache=mock_cache, rate_delay=0)

            mock_get.assert_not_called()  # API was NOT hit
            assert result["gleif_lei"] == "CACHED123"

    def test_cache_miss_stores_empty_result(self):
        """When API returns no results, cache the empty result to avoid re-querying."""
        mock_cache = MagicMock()
        mock_cache.get.return_value = None

        with patch("enrich_gleif.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = EMPTY_RESPONSE
            mock_get.return_value = mock_resp

            result = query_gleif("Unknown Corp", cache=mock_cache, rate_delay=0)

            mock_cache.set.assert_called_once()  # empty result was cached
            assert result["gleif_lei"] == ""


# ============================================================
# Rate Limiting (1 test)
# ============================================================

class TestRateLimiting:

    def test_respects_rate_delay(self):
        """Verify sequential API calls include the configured delay."""
        mock_cache = MagicMock()
        mock_cache.get.return_value = None

        with patch("enrich_gleif.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = EMPTY_RESPONSE
            mock_get.return_value = mock_resp

            with patch("enrich_gleif.time.sleep") as mock_sleep:
                query_gleif("Corp A", cache=mock_cache, rate_delay=0.5)
                mock_sleep.assert_called_with(0.5)


# ============================================================
# Modifier Math (2 tests — uses fingerprint engine)
# ============================================================

class TestGleifModifiers:

    def test_active_gleif_reduces_confidence(self):
        """An ACTIVE gleif_status should apply a -15 delta."""
        from match_fingerprints import calculate_confidence, validate_fingerprint

        fp = {
            "id": "FP-TEST", "name": "Test", "description": "", "version": 1,
            "indicators": [{"field": "asn", "match_type": "exact", "value": "16276", "required": True}],
            "confidence_base": 70,
            "confidence_modifiers": [
                {"field": "gleif_status", "match_type": "exact", "value": "ACTIVE", "delta": -15},
            ],
            "flame_tp_ids": [], "ttl_days": 30,
        }
        fp = validate_fingerprint(fp, source="test")
        row = {"asn": "16276", "gleif_status": "ACTIVE"}
        assert calculate_confidence(fp, row) == 55

    def test_missing_lei_increases_confidence(self):
        """An empty gleif_lei should apply a +10 delta."""
        from match_fingerprints import calculate_confidence, validate_fingerprint

        fp = {
            "id": "FP-TEST", "name": "Test", "description": "", "version": 1,
            "indicators": [{"field": "asn", "match_type": "exact", "value": "16276", "required": True}],
            "confidence_base": 70,
            "confidence_modifiers": [
                {"field": "gleif_lei", "match_type": "exact", "value": "", "delta": 10},
            ],
            "flame_tp_ids": [], "ttl_days": 30,
        }
        fp = validate_fingerprint(fp, source="test")
        row = {"asn": "16276", "gleif_lei": ""}
        assert calculate_confidence(fp, row) == 80
```

**Step 2: Write `scripts/enrich_gleif.py`**

```python
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
```

**Step 3: Run tests**

Run: `pytest tests/test_gleif.py -v`
Expected: 11 passed

**Step 4: Run full test suite for regressions**

Run: `pytest tests/ -q`
Expected: All tests pass (152+ existing + 11 new)

**Step 5: Commit**

```bash
git add scripts/enrich_gleif.py tests/test_gleif.py
git commit -m "feat: add GLEIF entity verification enrichment with tests"
```

---

### Task 3: Update Fingerprint YAML Files with GLEIF Modifiers

**Files:**
- Modify: `config/fingerprints/FP-0001-ovh-cpanel-dea.yaml`
- Modify: `config/fingerprints/FP-0002-alibaba-sideloading.yaml`
- Modify: `config/fingerprints/FP-0003-crypto-finance-cohosting.yaml`
- Modify: `config/fingerprints/FP-0004-gname-cloudflare-china.yaml`
- Modify: `config/fingerprints/FP-0005-godaddy-bulk-registration.yaml`
- Modify: `config/fingerprints/FP-0006-shell-domain-mx-cluster.yaml`
- Modify: `config/fingerprints/FP-0007-typosquat-evasion-infra.yaml`

**Step 1: Add GLEIF modifiers to all 7 fingerprints**

Append these two modifiers to the `confidence_modifiers` section of each YAML file:

```yaml
  - field: gleif_status
    match_type: exact
    value: "ACTIVE"
    delta: -15
  - field: gleif_lei
    match_type: exact
    value: ""
    delta: 10
```

**Step 2: Verify all fingerprints still load**

Run: `python -c "import sys; sys.path.insert(0,'scripts'); from match_fingerprints import load_fingerprints; fps=load_fingerprints(); print(f'{len(fps)} loaded'); [print(f'  {fp[\"id\"]}: {len(fp.get(\"confidence_modifiers\",[]))} modifiers') for fp in fps]"`

Expected: 7 loaded, each with 2 more modifiers than before.

**Step 3: Run fingerprint tests**

Run: `pytest tests/test_fingerprints.py tests/test_gleif.py -v`
Expected: All pass

**Step 4: Commit**

```bash
git add config/fingerprints/
git commit -m "feat: add GLEIF confidence modifiers to all 7 fingerprints"
```

---

### Task 4: Pipeline Integration

**Files:**
- Modify: `.github/workflows/update_intelligence.yml:222-224` (add step)

**Step 1: Add GLEIF workflow step**

Insert a new step AFTER "Data Hygiene & Enrichment (Clean Data)" (line 222) and BEFORE "Infrastructure Fingerprinting" (line 224):

```yaml
      - name: GLEIF Entity Verification
        timeout-minutes: 30
        continue-on-error: true
        run: python scripts/enrich_gleif.py
```

`continue-on-error: true` because GLEIF is a public API and shouldn't block the pipeline if it's down.

Also add to the "Commit and Push changes" step's file copy section:

```
          cp data/.gleif_cache/cache.db docs/data/ || true
```

Wait — actually, don't publish the cache DB. Just ensure `data/.gleif_cache/` is in `.gitignore` so it doesn't get committed. Check if `.gitignore` exists and add the path.

**Step 2: Verify workflow syntax**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/update_intelligence.yml')); print('Valid YAML')"`
Expected: `Valid YAML`

**Step 3: Commit**

```bash
git add .github/workflows/update_intelligence.yml
git commit -m "ci: add GLEIF entity verification step to pipeline workflow"
```

---

### Task 5: End-to-End Validation

**Step 1: Run against synthetic data**

Create a small test CSV and run the enrichment:

```bash
echo "domain,registrant_org,ssl_org,asn,nameservers,primary_mx" > /tmp/test_gleif_input.csv
echo "apple.com,Apple Inc.,,16276,ns1.apple.com,mx.apple.com" >> /tmp/test_gleif_input.csv
echo "unknown-shell.com,,,,ns1.example.com,mx.example.com" >> /tmp/test_gleif_input.csv
echo "google.com,,Google LLC,15169,ns1.google.com,mx.google.com" >> /tmp/test_gleif_input.csv
python scripts/enrich_gleif.py --input /tmp/test_gleif_input.csv --output /tmp/test_gleif_output.csv --limit 3
```

Inspect the output:
```bash
head -5 /tmp/test_gleif_output.csv
```

Expected: `apple.com` and `google.com` should have GLEIF LEI data. `unknown-shell.com` should have empty GLEIF columns.

**Step 2: Run full test suite**

Run: `pytest tests/ -q`
Expected: All tests pass

**Step 3: Commit any final adjustments**

```bash
git add -A
git commit -m "test: validate GLEIF enrichment end-to-end"
```
