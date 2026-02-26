# FP-0007 Typosquat Evasion Infrastructure — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable FP-0007 to fire by capturing HTTP redirects, cross-referencing dnstwist output, and updating FLAME threat paths with evasion technique documentation.

**Architecture:** Modify `probe_web.py` to extract redirect info via `response.history` (2 new columns). Create `enrich_dnstwist.py` to join pipeline CSV against `data/potential_typosquats.csv` (6 new columns). Rewrite FP-0007 YAML with dnstwist_match gate + evidence-based modifiers. Update 3 FLAME threat paths with new "Evasion Techniques" section. Create FLAME `docs/METHODOLOGY.md`.

**Tech Stack:** Python 3.10, aiohttp (existing), csv, pytest, YAML fingerprint engine

---

### Task 1: Redirect Capture in probe_web.py

**Files:**
- Modify: `scripts/probe_web.py:29-64` (fetch function) and `scripts/probe_web.py:85-95` (_probe_domain function) and `scripts/probe_web.py:117` (new_cols list)
- Create: `tests/test_probe_web.py`

**Context:** `probe_web.py` is an async domain prober using aiohttp. The `fetch()` function (line 29) makes GET requests with `allow_redirects=True` and returns a dict with `status`, `server`, `title`. The `_probe_domain()` function (line 85) calls `fetch()` twice (HTTP and HTTPS) and writes results to the row dict. The `new_cols` list (line 117) defines output columns.

The problem: `allow_redirects=True` means `response.status` is the final status (200), not the initial 301/302. We need to extract redirect info from `response.history` without changing existing behavior.

**Step 1: Write the failing test**

Create `tests/test_probe_web.py`:

```python
#!/usr/bin/env python3
"""Tests for probe_web.py — redirect capture and title extraction."""

import sys
import os
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from probe_web import fetch, get_title


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    """Run an async coroutine synchronously for testing."""
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_mock_response(status=200, headers=None, text="", history=None):
    """Create a mock aiohttp response."""
    resp = AsyncMock()
    resp.status = status
    resp.headers = headers or {}
    resp.text = AsyncMock(return_value=text)
    resp.history = history or ()
    return resp


def _make_mock_redirect_response():
    """Create a mock response that went through a 301 redirect.

    Simulates: GET http://evil.com -> 301 Location: https://brand.com -> 200
    """
    # The initial redirect response (in history)
    redirect_resp = MagicMock()
    redirect_resp.status = 301
    redirect_resp.headers = {"Location": "https://brand.com/"}

    # The final response (after following redirect)
    final_resp = AsyncMock()
    final_resp.status = 200
    final_resp.headers = {"Server": "nginx"}
    final_resp.text = AsyncMock(return_value="<html><title>Brand Page</title></html>")
    final_resp.history = (redirect_resp,)
    return final_resp


# ---------------------------------------------------------------------------
# TestGetTitle
# ---------------------------------------------------------------------------

class TestGetTitle:
    def test_extracts_title_from_html(self):
        assert get_title("<html><title>Hello World</title></html>") == "Hello World"

    def test_returns_empty_for_no_title(self):
        assert get_title("<html><body>No title</body></html>") == ""

    def test_returns_empty_for_none(self):
        assert get_title(None) == ""

    def test_truncates_long_title(self):
        long = "A" * 200
        result = get_title(f"<title>{long}</title>")
        assert len(result) == 100


# ---------------------------------------------------------------------------
# TestFetchRedirectCapture
# ---------------------------------------------------------------------------

class TestFetchRedirectCapture:
    """Verify that fetch() captures redirect_status and redirect_target from response.history."""

    def test_redirect_captured_from_history(self):
        """When response.history has a 301, fetch should return redirect_status and redirect_target."""
        mock_resp = _make_mock_redirect_response()

        mock_session = MagicMock()
        mock_session.get = MagicMock()
        mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch('probe_web.asyncio.sleep', new_callable=AsyncMock):
            result = _run(fetch(mock_session, "http://evil.com"))

        assert result["redirect_status"] == "301"
        assert result["redirect_target"] == "https://brand.com/"
        assert result["status"] == "200"
        assert result["title"] == "Brand Page"

    def test_no_redirect_returns_empty(self):
        """When no redirect (direct 200), redirect fields should be empty."""
        mock_resp = _make_mock_response(
            status=200,
            headers={"Server": "apache"},
            text="<html><title>Direct</title></html>",
            history=()
        )

        mock_session = MagicMock()
        mock_session.get = MagicMock()
        mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch('probe_web.asyncio.sleep', new_callable=AsyncMock):
            result = _run(fetch(mock_session, "http://example.com"))

        assert result["redirect_status"] == ""
        assert result["redirect_target"] == ""

    def test_connection_error_returns_empty_redirect_fields(self):
        """When connection fails, all fields including redirect should be empty."""
        import aiohttp
        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=aiohttp.ClientError("fail"))

        with patch('probe_web.asyncio.sleep', new_callable=AsyncMock):
            result = _run(fetch(mock_session, "http://down.com"))

        assert result["redirect_status"] == ""
        assert result["redirect_target"] == ""
        assert result["status"] == ""
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_probe_web.py -v`
Expected: FAIL — `KeyError: 'redirect_status'` (field doesn't exist yet)

**Step 3: Implement redirect capture in fetch()**

In `scripts/probe_web.py`, modify the `fetch()` function:

1. Add redirect fields to the initial result dict (line 30-34):
```python
async def fetch(session: aiohttp.ClientSession, url: str, proxy: str = None) -> Dict[str, str]:
    result = {
        "status": "",
        "server": "",
        "title": "",
        "redirect_status": "",
        "redirect_target": ""
    }
```

2. After `result["server"] = ...` (line 53), add redirect capture:
```python
            result["server"] = response.headers.get("Server", "")
            # Capture redirect info from history
            if response.history:
                result["redirect_status"] = str(response.history[0].status)
                result["redirect_target"] = str(response.history[0].headers.get("Location", ""))
```

3. In `_probe_domain()` (line 85-95), add the new columns to row assignment:
```python
async def _probe_domain(row: dict, domain: str, session: aiohttp.ClientSession, proxy: str):
    """Probe a single domain via HTTP and HTTPS."""
    task_https = fetch(session, f"https://{domain}", proxy)
    task_http = fetch(session, f"http://{domain}", proxy)
    res_https, res_http = await asyncio.gather(task_https, task_http)
    row["https_status"] = res_https["status"]
    row["https_server"] = res_https["server"]
    row["https_title"] = res_https["title"]
    row["http_status"] = res_http["status"]
    row["http_server"] = res_http["server"]
    row["http_title"] = res_http["title"]
    row["http_redirect_status"] = res_http["redirect_status"]
    row["http_redirect_target"] = res_http["redirect_target"]
```

4. In `prober()`, update the `new_cols` list (line 117):
```python
    new_cols = ["http_status", "http_title", "http_server", "https_status", "https_title", "https_server",
                "http_redirect_status", "http_redirect_target"]
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_probe_web.py -v`
Expected: All 7 tests PASS

**Step 5: Commit**

```bash
git add tests/test_probe_web.py scripts/probe_web.py
git commit -m "feat: capture HTTP redirect status and target in probe_web.py"
```

---

### Task 2: dnstwist Cross-Reference Enrichment Script

**Files:**
- Create: `scripts/enrich_dnstwist.py`
- Create: `tests/test_dnstwist_enrich.py`

**Context:** `data/potential_typosquats.csv` has columns: `domain, dns_a, dns_aaaa, dns_mx, dns_ns, fuzzer, source_target`. It contains ~17K rows from dnstwist scans. The pipeline CSV (`data/dea_domains_probed.csv`) contains all enriched domains. This script joins the two, adding 6 new columns. It runs AFTER data hygiene and BEFORE fingerprinting in the workflow.

The existing enrichment pattern (see `scripts/enrich_gleif.py`, `scripts/enrich_opensanctions.py`) is: read input CSV → enrich rows → write back to same file (in-place update). This script follows that pattern.

**Step 1: Write the failing tests**

Create `tests/test_dnstwist_enrich.py`:

```python
#!/usr/bin/env python3
"""Tests for enrich_dnstwist.py — dnstwist cross-reference enrichment."""

import sys
import os
import csv
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from enrich_dnstwist import (
    load_dnstwist_lookup,
    extract_brand_name,
    check_redirects_to_brand,
    check_registrant_mismatch,
    enrich_row,
)


# ---------------------------------------------------------------------------
# TestLoadDnstwistLookup
# ---------------------------------------------------------------------------

class TestLoadDnstwistLookup:
    """Verify loading potential_typosquats.csv into a lookup dict."""

    def test_loads_csv_into_dict(self, tmp_path):
        csv_file = tmp_path / "typosquats.csv"
        csv_file.write_text(
            "domain,dns_a,dns_aaaa,dns_mx,dns_ns,fuzzer,source_target\n"
            "amaz0n.com,1.2.3.4,,mx.evil.com,ns1.evil.com,homoglyph,amazon.com\n"
            "g00gle.com,5.6.7.8,,,,addition,google.com\n"
        )
        lookup = load_dnstwist_lookup(str(csv_file))
        assert "amaz0n.com" in lookup
        assert lookup["amaz0n.com"]["fuzzer"] == "homoglyph"
        assert lookup["amaz0n.com"]["source_target"] == "amazon.com"
        assert "g00gle.com" in lookup

    def test_missing_file_returns_empty(self, tmp_path):
        lookup = load_dnstwist_lookup(str(tmp_path / "nonexistent.csv"))
        assert lookup == {}

    def test_empty_file_returns_empty(self, tmp_path):
        csv_file = tmp_path / "empty.csv"
        csv_file.write_text("domain,dns_a,dns_aaaa,dns_mx,dns_ns,fuzzer,source_target\n")
        lookup = load_dnstwist_lookup(str(csv_file))
        assert lookup == {}


# ---------------------------------------------------------------------------
# TestExtractBrandName
# ---------------------------------------------------------------------------

class TestExtractBrandName:
    """Verify brand name extraction from domain."""

    def test_simple_domain(self):
        assert extract_brand_name("amazon.com") == "amazon"

    def test_subdomain(self):
        assert extract_brand_name("www.google.com") == "google"

    def test_two_part_tld(self):
        assert extract_brand_name("barclays.co.uk") == "barclays"

    def test_empty(self):
        assert extract_brand_name("") == ""


# ---------------------------------------------------------------------------
# TestCheckRedirectsToBrand
# ---------------------------------------------------------------------------

class TestCheckRedirectsToBrand:
    """Verify redirect-to-brand detection."""

    def test_redirect_to_brand(self):
        assert check_redirects_to_brand("https://amazon.com/", "amazon.com") is True

    def test_redirect_to_brand_subdomain(self):
        assert check_redirects_to_brand("https://www.amazon.com/login", "amazon.com") is True

    def test_redirect_to_unrelated(self):
        assert check_redirects_to_brand("https://parked-page.com/", "amazon.com") is False

    def test_empty_redirect(self):
        assert check_redirects_to_brand("", "amazon.com") is False


# ---------------------------------------------------------------------------
# TestCheckRegistrantMismatch
# ---------------------------------------------------------------------------

class TestCheckRegistrantMismatch:
    """Verify registrant mismatch detection."""

    def test_matching_registrant(self):
        assert check_registrant_mismatch("Amazon Technologies Inc", "amazon.com") is False

    def test_mismatching_registrant(self):
        assert check_registrant_mismatch("Evil Corp LLC", "amazon.com") is True

    def test_empty_registrant_defaults_true(self):
        assert check_registrant_mismatch("", "amazon.com") is True

    def test_case_insensitive(self):
        assert check_registrant_mismatch("AMAZON INC", "amazon.com") is False


# ---------------------------------------------------------------------------
# TestEnrichRow
# ---------------------------------------------------------------------------

class TestEnrichRow:
    """Verify full row enrichment with dnstwist lookup."""

    def test_matching_domain(self):
        lookup = {
            "amaz0n.com": {
                "fuzzer": "homoglyph",
                "source_target": "amazon.com",
            }
        }
        row = {
            "domain": "amaz0n.com",
            "http_redirect_target": "https://amazon.com/",
            "registrant_org": "Evil Corp",
            "https_status": "200",
        }
        enrich_row(row, lookup)
        assert row["dnstwist_match"] == "True"
        assert row["dnstwist_fuzzer"] == "homoglyph"
        assert row["dnstwist_target"] == "amazon.com"
        assert row["redirects_to_brand"] == "True"
        assert row["registrant_mismatch"] == "True"
        assert row["ssl_present"] == "True"

    def test_non_matching_domain(self):
        lookup = {}
        row = {
            "domain": "legitimate.com",
            "http_redirect_target": "",
            "registrant_org": "Legit Inc",
            "https_status": "",
        }
        enrich_row(row, lookup)
        assert row["dnstwist_match"] == "False"
        assert row["dnstwist_fuzzer"] == ""
        assert row["dnstwist_target"] == ""
        assert row["redirects_to_brand"] == "False"
        assert row["registrant_mismatch"] == "False"
        assert row["ssl_present"] == "False"

    def test_match_but_no_redirect(self):
        lookup = {
            "g00gle.com": {
                "fuzzer": "addition",
                "source_target": "google.com",
            }
        }
        row = {
            "domain": "g00gle.com",
            "http_redirect_target": "",
            "registrant_org": "",
            "https_status": "200",
        }
        enrich_row(row, lookup)
        assert row["dnstwist_match"] == "True"
        assert row["redirects_to_brand"] == "False"
        assert row["registrant_mismatch"] == "True"  # empty = unknown = True
        assert row["ssl_present"] == "True"


# ---------------------------------------------------------------------------
# TestEndToEnd
# ---------------------------------------------------------------------------

class TestEndToEnd:
    """Verify full CSV enrichment pipeline."""

    def test_enriches_csv_file(self, tmp_path):
        # Create dnstwist lookup
        twist_file = tmp_path / "potential_typosquats.csv"
        twist_file.write_text(
            "domain,dns_a,dns_aaaa,dns_mx,dns_ns,fuzzer,source_target\n"
            "amaz0n.com,1.2.3.4,,mx.evil.com,ns1.evil.com,homoglyph,amazon.com\n"
        )

        # Create pipeline input
        input_file = tmp_path / "input.csv"
        input_file.write_text(
            "domain,http_redirect_target,registrant_org,https_status\n"
            "amaz0n.com,https://amazon.com/,Evil Corp,200\n"
            "legitimate.com,,,\n"
        )

        output_file = tmp_path / "output.csv"

        # Import and run
        from enrich_dnstwist import run
        run(
            input_file=str(input_file),
            output_file=str(output_file),
            dnstwist_file=str(twist_file),
        )

        # Verify output
        with open(output_file, "r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2
        assert rows[0]["dnstwist_match"] == "True"
        assert rows[0]["redirects_to_brand"] == "True"
        assert rows[1]["dnstwist_match"] == "False"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_dnstwist_enrich.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'enrich_dnstwist'`

**Step 3: Write minimal implementation**

Create `scripts/enrich_dnstwist.py`:

```python
#!/usr/bin/env python3
"""
enrich_dnstwist.py

Cross-references pipeline domains against dnstwist output
(data/potential_typosquats.csv) to identify confirmed typosquats
and derive evasion signals for FP-0007 fingerprinting.

New columns added:
  - dnstwist_match: True/False
  - dnstwist_fuzzer: fuzzer technique (homoglyph, addition, etc.)
  - dnstwist_target: brand domain being impersonated
  - redirects_to_brand: True if HTTP redirect target contains brand domain
  - registrant_mismatch: True if registrant_org doesn't contain brand name
  - ssl_present: True if https_status is non-empty
"""

import argparse
import csv
import logging
import os
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_INPUT = "data/dea_domains_probed.csv"
DEFAULT_OUTPUT = "data/dea_domains_probed.csv"  # in-place enrichment
DEFAULT_DNSTWIST = "data/potential_typosquats.csv"

NEW_COLUMNS = [
    "dnstwist_match",
    "dnstwist_fuzzer",
    "dnstwist_target",
    "redirects_to_brand",
    "registrant_mismatch",
    "ssl_present",
]


# ---------------------------------------------------------------------------
# Lookup loading
# ---------------------------------------------------------------------------

def load_dnstwist_lookup(dnstwist_file: str) -> Dict[str, dict]:
    """Load dnstwist CSV into a domain→record lookup dict.

    Returns empty dict if file is missing or empty.
    """
    if not os.path.isfile(dnstwist_file):
        logger.warning("dnstwist file not found: %s", dnstwist_file)
        return {}

    lookup = {}
    try:
        with open(dnstwist_file, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain = row.get("domain", "").strip().lower()
                if domain:
                    lookup[domain] = {
                        "fuzzer": row.get("fuzzer", ""),
                        "source_target": row.get("source_target", ""),
                    }
    except OSError as exc:
        logger.error("Failed to read dnstwist file: %s", exc)
        return {}

    logger.info("Loaded %d dnstwist entries from %s", len(lookup), dnstwist_file)
    return lookup


# ---------------------------------------------------------------------------
# Derived-field logic
# ---------------------------------------------------------------------------

def extract_brand_name(domain: str) -> str:
    """Extract the brand name from a domain (the main label before the TLD).

    Examples:
        amazon.com -> amazon
        www.google.com -> google
        barclays.co.uk -> barclays
    """
    if not domain:
        return ""
    parts = domain.lower().strip().split(".")
    # Common two-part TLDs
    two_part_tlds = {"co.uk", "com.au", "co.jp", "co.kr", "com.br", "co.in"}
    if len(parts) >= 3:
        tld_candidate = f"{parts[-2]}.{parts[-1]}"
        if tld_candidate in two_part_tlds:
            return parts[-3] if len(parts) >= 3 else parts[0]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def check_redirects_to_brand(redirect_target: str, brand_domain: str) -> bool:
    """Check if redirect target URL contains the brand domain."""
    if not redirect_target or not brand_domain:
        return False
    return brand_domain.lower() in redirect_target.lower()


def check_registrant_mismatch(registrant_org: str, brand_domain: str) -> bool:
    """Check if registrant org does NOT contain the brand name.

    Empty registrant_org defaults to True (unknown = suspicious).
    """
    if not registrant_org or not registrant_org.strip():
        return True
    brand = extract_brand_name(brand_domain)
    if not brand:
        return False
    return brand.lower() not in registrant_org.lower()


# ---------------------------------------------------------------------------
# Row enrichment
# ---------------------------------------------------------------------------

def enrich_row(row: dict, lookup: Dict[str, dict]) -> None:
    """Enrich a single row with dnstwist cross-reference data. Modifies row in place."""
    domain = row.get("domain", "").strip().lower()
    entry = lookup.get(domain)

    if entry:
        target = entry.get("source_target", "")
        row["dnstwist_match"] = "True"
        row["dnstwist_fuzzer"] = entry.get("fuzzer", "")
        row["dnstwist_target"] = target
        row["redirects_to_brand"] = str(check_redirects_to_brand(
            row.get("http_redirect_target", ""), target
        ))
        row["registrant_mismatch"] = str(check_registrant_mismatch(
            row.get("registrant_org", ""), target
        ))
        row["ssl_present"] = str(bool(row.get("https_status", "").strip()))
    else:
        row["dnstwist_match"] = "False"
        row["dnstwist_fuzzer"] = ""
        row["dnstwist_target"] = ""
        row["redirects_to_brand"] = "False"
        row["registrant_mismatch"] = "False"
        row["ssl_present"] = "False"


# ---------------------------------------------------------------------------
# Pipeline run
# ---------------------------------------------------------------------------

def run(input_file: str = DEFAULT_INPUT,
        output_file: str = DEFAULT_OUTPUT,
        dnstwist_file: str = DEFAULT_DNSTWIST) -> int:
    """Run the dnstwist cross-reference enrichment.

    Reads input CSV, enriches each row, writes output CSV.
    Returns count of matched domains.
    """
    lookup = load_dnstwist_lookup(dnstwist_file)
    if not lookup:
        logger.warning("Empty dnstwist lookup — writing passthrough (no enrichment)")

    if not os.path.isfile(input_file):
        logger.error("Input file not found: %s", input_file)
        return 0

    rows = []
    fieldnames = []
    with open(input_file, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames) if reader.fieldnames else []
        rows = list(reader)

    # Add new columns
    for col in NEW_COLUMNS:
        if col not in fieldnames:
            fieldnames.append(col)

    match_count = 0
    for row in rows:
        enrich_row(row, lookup)
        if row.get("dnstwist_match") == "True":
            match_count += 1

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    logger.info(
        "Enriched %d rows, %d dnstwist matches, written to %s",
        len(rows), match_count, output_file,
    )
    return match_count


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Cross-reference pipeline domains against dnstwist output."
    )
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Input CSV")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output CSV")
    parser.add_argument(
        "--dnstwist-file", default=DEFAULT_DNSTWIST,
        help="Path to dnstwist results CSV"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    count = run(
        input_file=args.input,
        output_file=args.output,
        dnstwist_file=args.dnstwist_file,
    )
    logger.info("Total dnstwist matches: %d", count)


if __name__ == "__main__":
    main()
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_dnstwist_enrich.py -v`
Expected: All 16 tests PASS

**Step 5: Commit**

```bash
git add scripts/enrich_dnstwist.py tests/test_dnstwist_enrich.py
git commit -m "feat: add dnstwist cross-reference enrichment script"
```

---

### Task 3: Rewrite FP-0007 YAML

**Files:**
- Modify: `config/fingerprints/FP-0007-typosquat-evasion-infra.yaml` (full replacement)

**Context:** The current FP-0007 can never fire because:
1. `http_status regex ^3\d\d$` requires a 3xx status, but `probe_web.py` follows redirects (returns final 200)
2. `risk_tags contains "typosquat"` requires a field that nothing populates

The new version uses `dnstwist_match` as the required gate (populated by Task 2), with evidence-based modifiers. See design doc: `docs/plans/2026-02-26-fp0007-typosquat-design.md` section 3.

**Step 1: Write a test for the new FP-0007 schema**

Add to `tests/test_fingerprints.py` (append at end of file):

```python
# ---------------------------------------------------------------------------
# TestFP0007Typosquat
# ---------------------------------------------------------------------------

class TestFP0007Typosquat:
    """Validate the rewritten FP-0007 fires correctly with dnstwist data."""

    def test_fires_on_dnstwist_match(self):
        """FP-0007 should fire when dnstwist_match is True."""
        fp = _make_fp(
            id="FP-0007",
            name="Typosquat Evasion Infrastructure",
            indicators=[
                {"field": "dnstwist_match", "match_type": "exact", "value": "True", "required": True},
            ],
            confidence_base=45,
            confidence_modifiers=[
                {"field": "redirects_to_brand", "match_type": "exact", "value": "True", "delta": 30},
                {"field": "primary_mx", "match_type": "contains", "value": ".", "delta": 20},
                {"field": "registrant_mismatch", "match_type": "exact", "value": "True", "delta": 15},
            ],
            flame_tp_ids=["TP-0012"],
        )
        fp = validate_fingerprint(fp, source="test")
        row = _make_row(
            domain="amaz0n.com",
            dnstwist_match="True",
            redirects_to_brand="True",
            primary_mx="mx.evilhost.com",
            registrant_mismatch="True",
        )
        result = evaluate_fingerprint(fp, row)
        assert result is not None
        assert result["fp_id"] == "FP-0007"
        assert result["confidence"] == 100  # 45 + 30 + 20 + 15 = 110, clamped to 100

    def test_does_not_fire_without_dnstwist_match(self):
        """FP-0007 should NOT fire when dnstwist_match is False."""
        fp = _make_fp(
            id="FP-0007",
            indicators=[
                {"field": "dnstwist_match", "match_type": "exact", "value": "True", "required": True},
            ],
            confidence_base=45,
        )
        fp = validate_fingerprint(fp, source="test")
        row = _make_row(dnstwist_match="False")
        assert evaluate_fingerprint(fp, row) is None

    def test_base_score_with_no_modifiers_matching(self):
        """With only dnstwist_match, score should be base 45."""
        fp = _make_fp(
            id="FP-0007",
            indicators=[
                {"field": "dnstwist_match", "match_type": "exact", "value": "True", "required": True},
            ],
            confidence_base=45,
            confidence_modifiers=[
                {"field": "redirects_to_brand", "match_type": "exact", "value": "True", "delta": 30},
            ],
        )
        fp = validate_fingerprint(fp, source="test")
        row = _make_row(dnstwist_match="True", redirects_to_brand="False")
        result = evaluate_fingerprint(fp, row)
        assert result is not None
        assert result["confidence"] == 45

    def test_yaml_loads_successfully(self):
        """The actual FP-0007 YAML file should load and validate."""
        import yaml
        yaml_path = os.path.join(
            os.path.dirname(__file__), '..', 'config', 'fingerprints',
            'FP-0007-typosquat-evasion-infra.yaml'
        )
        with open(yaml_path, 'r') as f:
            fp = yaml.safe_load(f)
        result = validate_fingerprint(fp, source=yaml_path)
        assert result["id"] == "FP-0007"
        assert result["confidence_base"] == 45
        # Verify the required gate
        required_indicators = [i for i in result["indicators"] if i.get("required")]
        assert len(required_indicators) == 1
        assert required_indicators[0]["field"] == "dnstwist_match"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_fingerprints.py::TestFP0007Typosquat -v`
Expected: FAIL — `test_yaml_loads_successfully` fails because YAML still has old schema (confidence_base=75, risk_tags indicator)

**Step 3: Rewrite the FP-0007 YAML**

Replace the entire contents of `config/fingerprints/FP-0007-typosquat-evasion-infra.yaml`:

```yaml
id: "FP-0007"
name: "Typosquat Evasion Infrastructure"
description: >
  Domains confirmed as typosquats (via dnstwist) exhibiting evasion
  behaviors: strategic redirects to brand, active MX, registrant
  mismatch, or sanctions matches.
version: 2

indicators:
  - field: dnstwist_match
    match_type: exact
    value: "True"
    required: true

confidence_base: 45

confidence_modifiers:
  - field: redirects_to_brand
    match_type: exact
    value: "True"
    delta: 30
  - field: primary_mx
    match_type: contains
    value: "."
    delta: 20
  - field: registrant_mismatch
    match_type: exact
    value: "True"
    delta: 15
  - field: http_title
    match_type: regex
    value: "(?i)(parked|for sale|buy this|domain for sale)"
    delta: 10
  - field: os_match_score
    match_type: range
    value: "70-100"
    delta: 20
  - field: ssl_present
    match_type: exact
    value: "True"
    delta: 5
  - field: vt_malicious_count
    match_type: range
    value: "3-100"
    delta: 20
  - field: phishtank_match
    match_type: exact
    value: "True"
    delta: 15

flame_tp_ids:
  - "TP-0012"

ttl_days: 30
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_fingerprints.py::TestFP0007Typosquat -v`
Expected: All 4 tests PASS

Also run the full fingerprint test suite to ensure nothing broke:

Run: `pytest tests/test_fingerprints.py -v`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add config/fingerprints/FP-0007-typosquat-evasion-infra.yaml tests/test_fingerprints.py
git commit -m "feat: rewrite FP-0007 YAML with dnstwist_match gate and evidence modifiers"
```

---

### Task 4: Pipeline Integration (Workflow YAML)

**Files:**
- Modify: `.github/workflows/update_intelligence.yml:237-240` (insert dnstwist step before fingerprinting)

**Context:** The dnstwist enrichment step must run AFTER data hygiene (clean_data.py, enrich_asns.py at line 218-222) and AFTER ICIJ (line 237), but BEFORE Infrastructure Fingerprinting (line 239-240). This is because enrich_dnstwist.py adds columns that FP-0007 needs to evaluate.

**Step 1: No test needed** (YAML integration — tested by existing CI and Task 5 E2E)

**Step 2: Add the workflow step**

In `.github/workflows/update_intelligence.yml`, insert AFTER the ICIJ step (line 237) and BEFORE "Infrastructure Fingerprinting" (line 239):

```yaml
      - name: dnstwist Cross-Reference Enrichment
        run: python scripts/enrich_dnstwist.py
```

The full sequence should read:
```yaml
      - name: ICIJ OffshoreLeaks Screening
        timeout-minutes: 30
        continue-on-error: true
        run: python scripts/enrich_icij.py

      - name: dnstwist Cross-Reference Enrichment
        run: python scripts/enrich_dnstwist.py

      - name: Infrastructure Fingerprinting
        run: python scripts/match_fingerprints.py
```

**Step 3: Commit**

```bash
git add .github/workflows/update_intelligence.yml
git commit -m "feat: add dnstwist enrichment step to CI pipeline before fingerprinting"
```

---

### Task 5: FLAME Threat Path Updates (flame-fraud repo)

**Files (in `C:\Users\anon\Documents\anon\repos\flame-fraud`):**
- Modify: `ThreatPaths/TP-0001-treasury-mgmt-ato-malvertising.md:130-132` (insert between CFPF Phase Mapping and Look Left/Right)
- Modify: `ThreatPaths/TP-0002-bec-vendor-impersonation-wire.md:87-88` (insert between CFPF Phase Mapping and Look Left/Right)
- Modify: `ThreatPaths/TP-0017-pig-butchering.md:113-115` (insert between CFPF Phase Mapping and Look Left/Right)
- Create: `docs/METHODOLOGY.md`

**Context:** This task operates on a DIFFERENT repo: `C:\Users\anon\Documents\anon\repos\flame-fraud`. The FLAME threat paths currently have no "Evasion Techniques" sections. Per the approved design, we add a table-format section between "CFPF Phase Mapping" and "Look Left / Look Right Analysis". Each threat path gets different applicable techniques.

**Step 1: No automated tests** (documentation-only changes)

**Step 2: Add Evasion Techniques to TP-0001**

In `ThreatPaths/TP-0001-treasury-mgmt-ato-malvertising.md`, insert BEFORE `## Look Left / Look Right Analysis` (line 132):

```markdown
## Evasion Techniques

| Technique | Description | Detection Signal |
|-----------|-------------|------------------|
| Strategic HTTP Redirect | Typosquat domain 301/302 redirects to legitimate bank site to appear benign in automated scans; once a real user visits, the redirect may serve a credential harvesting page instead | FP-0007: `redirects_to_brand=True` in domain_intel |
| Domain Sale Page Camouflage | Domain displays "for sale" or "parked" page to automated scanners, evading malicious classification while remaining operational for targeted victims | FP-0007: `http_title` matches parked/sale pattern in domain_intel |

**Source**: CrowdStrike Counter Adversary Operations — "Dual-Purpose Domains" and "Domain Sale Page Camouflage" research on typosquatting evasion techniques.

---

```

**Step 3: Add Evasion Techniques to TP-0002**

In `ThreatPaths/TP-0002-bec-vendor-impersonation-wire.md`, insert BEFORE `## Look Left / Look Right` (line 88):

```markdown
## Evasion Techniques

| Technique | Description | Detection Signal |
|-----------|-------------|------------------|
| Strategic HTTP Redirect | Lookalike vendor domain redirects to the real vendor's website; appears legitimate in basic checks, but email from the domain reaches the attacker | FP-0007: `redirects_to_brand=True` in domain_intel |
| Geo-Targeted Content | Domain serves different content based on visitor geography — benign pages for scanners/researchers in certain regions, malicious content for targets | Manual verification required; inconsistent scan results across geolocations |

**Source**: CrowdStrike Counter Adversary Operations — typosquatting evasion research.

---

```

**Step 4: Add Evasion Techniques to TP-0017**

In `ThreatPaths/TP-0017-pig-butchering.md`, insert BEFORE `## Look Left / Look Right Analysis` (line 115):

```markdown
## Evasion Techniques

| Technique | Description | Detection Signal |
|-----------|-------------|------------------|
| Domain Sale Page Camouflage | Fraudulent investment platform domain shows "for sale" or "coming soon" page to automated scanners, evading blocklists while remaining operational for victims directed via messaging apps | FP-0007: `http_title` matches parked/sale pattern in domain_intel |
| Geo-Targeted Content | Platform serves legitimate-looking content or blocks access from regions where law enforcement or researchers are likely based | Manual verification required; inconsistent scan results |

**Source**: CrowdStrike Counter Adversary Operations — typosquatting evasion research.

---

```

**Step 5: Create docs/METHODOLOGY.md**

Create `docs/METHODOLOGY.md` in the flame-fraud repo:

```markdown
# FLAME Detection Methodology

## Typosquat Detection

### Pipeline

1. **dnstwist fuzzing** (`scripts/generate_permutations.py`): Generates domain permutations (homoglyph, addition, bitsquatting, etc.) for target brands listed in `config/targets.txt`
2. **DNS resolution**: dnstwist resolves A, AAAA, MX, NS records for each permutation to identify live domains
3. **Cross-reference** (`scripts/enrich_dnstwist.py`): Joins live typosquat domains against the main pipeline CSV, adding `dnstwist_match`, `dnstwist_fuzzer`, `dnstwist_target`, and derived evasion signals
4. **Fingerprinting** (`scripts/match_fingerprints.py`): FP-0007 evaluates cross-referenced domains for evasion indicators (redirects to brand, registrant mismatch, parked pages, etc.)

### Evasion Signals

| Signal | Source | Meaning |
|--------|--------|---------|
| `redirects_to_brand` | probe_web.py redirect capture + enrich_dnstwist.py | Domain 301/302 redirects to the brand it impersonates |
| `registrant_mismatch` | WHOIS data + enrich_dnstwist.py | Domain registrant does not contain the brand name |
| `ssl_present` | probe_web.py HTTPS probe | Domain has a valid TLS certificate (operational investment) |
| Parked/sale page | probe_web.py title extraction | Domain title matches parked/sale patterns |

### Known Limitations

- **No Levenshtein scoring**: The current pipeline uses exact dnstwist fuzzer matching, not edit-distance scoring. A domain that visually resembles a brand but wasn't generated by dnstwist will not be detected.
- **Geo-targeted content**: `probe_web.py` probes from a single geographic location (the GitHub Actions runner region). Domains serving different content to different regions will only show the runner's view.
- **Registrant heuristic**: Brand-name-in-registrant matching is a case-insensitive substring check. It will miss registrants using abbreviations, parent company names, or privacy services.
- **targets.txt dependency**: Only brands listed in `config/targets.txt` are fuzzed. New brands must be manually added.
```

**Step 6: Commit (in flame-fraud repo)**

```bash
cd C:\Users\anon\Documents\anon\repos\flame-fraud
git add ThreatPaths/TP-0001-treasury-mgmt-ato-malvertising.md
git add ThreatPaths/TP-0002-bec-vendor-impersonation-wire.md
git add ThreatPaths/TP-0017-pig-butchering.md
git add docs/METHODOLOGY.md
git commit -m "docs: add Evasion Techniques sections and detection methodology"
```

---

### Task 6: E2E Validation

**Files:** None (verification only)

**Context:** Validate the full integration: probe_web redirect capture → enrich_dnstwist → FP-0007 YAML → pipeline workflow.

**Step 1: Run all tests in domain_intel**

Run: `pytest tests/ -v`
Expected: ALL tests pass (probe_web, dnstwist_enrich, fingerprints, virustotal, phishtank, etc.)

**Step 2: Verify FP-0007 fires in integration**

Write and run a quick smoke test (do not commit — this is manual validation):

```bash
python -c "
import sys, os, csv, tempfile
sys.path.insert(0, 'scripts')
from match_fingerprints import load_fingerprints, match_domain

fps = load_fingerprints('config/fingerprints')
fp7 = [f for f in fps if f['id'] == 'FP-0007']
assert len(fp7) == 1, 'FP-0007 not loaded'

row = {
    'domain': 'amaz0n.com',
    'dnstwist_match': 'True',
    'dnstwist_fuzzer': 'homoglyph',
    'dnstwist_target': 'amazon.com',
    'redirects_to_brand': 'True',
    'registrant_mismatch': 'True',
    'ssl_present': 'True',
    'primary_mx': 'mx.evil.com',
    'http_title': 'Amazon - Shop Online',
    'os_match_score': '',
    'vt_malicious_count': '',
    'phishtank_match': '',
}
matches = match_domain(row, fp7)
assert len(matches) == 1, f'Expected 1 match, got {len(matches)}'
m = matches[0]
print(f'FP-0007 fires: confidence={m[\"confidence\"]}')
assert m['confidence'] == 100, f'Expected 100, got {m[\"confidence\"]}'  # 45+30+20+15 = 110 clamped to 100
print('PASS: FP-0007 integration verified')
"
```

Expected: `PASS: FP-0007 integration verified`

**Step 3: Verify workflow YAML is valid**

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/update_intelligence.yml')); print('YAML valid')"
```

Expected: `YAML valid`

**Step 4: Create GitHub issue**

Create the tracking issue per user's Step 2 request:

```bash
gh issue create --title "Implement FP-0007 Typosquat Evasion & FLAME Enrichment" --body "$(cat <<'ISSUE_EOF'
## Summary

Enable FP-0007 (Typosquat Evasion Infrastructure) to fire by capturing HTTP redirects, cross-referencing dnstwist output, and updating FLAME threat paths with evasion technique documentation.

Based on CrowdStrike Counter Adversary Operations research on "Dual-Purpose Domains" and "Domain Sale Page Camouflage."

## Part 1: domain_intel Repo

- [ ] Capture HTTP redirect status/target in `probe_web.py` via `response.history`
- [ ] Create `enrich_dnstwist.py` cross-reference script (6 new columns)
- [ ] Rewrite FP-0007 YAML with `dnstwist_match` gate + evidence modifiers
- [ ] Add dnstwist enrichment step to CI workflow (before fingerprinting)
- [ ] Tests for probe_web redirect capture
- [ ] Tests for enrich_dnstwist enrichment
- [ ] Tests for FP-0007 schema validation and scoring

## Part 2: FLAME Repo

- [ ] Add "Evasion Techniques" section to TP-0001 (Treasury Management ATO)
- [ ] Add "Evasion Techniques" section to TP-0002 (BEC Vendor Impersonation)
- [ ] Add "Evasion Techniques" section to TP-0017 (Pig Butchering)
- [ ] Create `docs/METHODOLOGY.md` with typosquat detection methodology and known limitations

## Design Docs

- Design: `docs/plans/2026-02-26-fp0007-typosquat-design.md`
- Plan: `docs/plans/2026-02-26-fp0007-typosquat-plan.md`
ISSUE_EOF
)"
```
