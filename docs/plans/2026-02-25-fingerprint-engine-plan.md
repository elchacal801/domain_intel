# FP-XXXX Infrastructure Fingerprinting Engine — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a YAML-driven infrastructure fingerprinting engine that scores domains against metadata patterns (NS, MX, ASN, registrar) and outputs confidence-scored matches.

**Architecture:** Per-file YAML fingerprints in `config/fingerprints/`, loaded by a linear scan matcher in `scripts/match_fingerprints.py`. Each domain row from `data/dea_domains_probed.csv` is evaluated against all fingerprints. Required indicators are AND-ed; confidence modifiers adjust a base score.

**Tech Stack:** Python 3.10, PyYAML (already in requirements.txt), pytest, csv, re, argparse, logging, glob.

**Design doc:** `docs/plans/2026-02-25-fingerprint-engine-design.md`

---

### Task 1: Schema Validation + Core Matching Functions (TDD)

**Files:**
- Create: `tests/test_fingerprints.py`
- Create: `scripts/match_fingerprints.py`

This task builds the core engine functions with tests first: loading/validating fingerprints, matching indicators, and scoring.

**Step 1: Write the test file with all 15+ test functions (tests fail because module doesn't exist yet)**

```python
#!/usr/bin/env python3
"""Tests for the infrastructure fingerprinting engine."""

import os
import sys
import re

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from match_fingerprints import (
    validate_fingerprint,
    resolve_field,
    check_indicator,
    evaluate_fingerprint,
    calculate_confidence,
    load_fingerprints_from_list,
    match_domain,
)


# --- Fixtures ---

def _make_fp(**overrides):
    """Build a minimal valid fingerprint dict with optional overrides."""
    base = {
        "id": "FP-TEST",
        "name": "Test Fingerprint",
        "description": "Unit test fingerprint",
        "version": 1,
        "indicators": [
            {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
        ],
        "confidence_base": 70,
        "confidence_modifiers": [],
        "flame_tp_ids": ["TP-0001"],
        "ttl_days": 30,
    }
    base.update(overrides)
    return base


def _make_row(**overrides):
    """Build a minimal domain CSV row dict."""
    base = {
        "domain": "test.example.com",
        "asn": "",
        "nameservers": "",
        "primary_mx": "",
        "registry": "",
        "cc": "",
        "http_title": "",
        "https_title": "",
        "risk_tags": "",
        "http_status": "",
        "mx_records": "",
    }
    base.update(overrides)
    return base


# ============================================================
# Schema Validation (3 tests)
# ============================================================

class TestSchemaValidation:

    def test_valid_fingerprint_loads(self):
        fp = _make_fp()
        validated = validate_fingerprint(fp, source="test")
        assert validated["id"] == "FP-TEST"

    def test_missing_required_key_raises(self):
        fp = _make_fp()
        del fp["id"]
        with pytest.raises(ValueError, match="id"):
            validate_fingerprint(fp, source="test")

    def test_unknown_match_type_raises(self):
        fp = _make_fp(indicators=[
            {"field": "asn", "match_type": "fuzzy", "value": "123", "required": True}
        ])
        with pytest.raises(ValueError, match="match_type"):
            validate_fingerprint(fp, source="test")


# ============================================================
# Field Alias Resolution (2 tests)
# ============================================================

class TestFieldAlias:

    def test_alias_ns_resolves_to_nameservers(self):
        assert resolve_field("ns") == "nameservers"

    def test_direct_column_name_passes_through(self):
        assert resolve_field("asn") == "asn"


# ============================================================
# Match Type Logic (5 tests)
# ============================================================

class TestMatchTypes:

    def test_exact_match(self):
        assert check_indicator("16276", "exact", "16276") is True

    def test_exact_match_case_insensitive(self):
        assert check_indicator("GoDaddy", "exact", "godaddy") is True

    def test_contains_match_in_semicolon_field(self):
        assert check_indicator("ns1.cprapid.com;ns2.cprapid.com", "contains", "cprapid.com") is True

    def test_regex_match(self):
        assert check_indicator("crypto-wallet-login.com", "regex", r"crypto.*login") is True

    def test_range_match_numeric(self):
        assert check_indicator("45102", "range", "45100-45110") is True

    def test_range_no_match_outside_bounds(self):
        assert check_indicator("99999", "range", "45100-45110") is False

    def test_contains_no_match(self):
        assert check_indicator("ns1.cloudflare.com", "contains", "cprapid.com") is False


# ============================================================
# Scoring Logic (4 tests)
# ============================================================

class TestScoring:

    def test_base_confidence_no_modifiers(self):
        fp = _make_fp(confidence_base=70, confidence_modifiers=[])
        row = _make_row(asn="16276")
        score = calculate_confidence(fp, row)
        assert score == 70

    def test_positive_delta_applied(self):
        fp = _make_fp(
            confidence_base=70,
            confidence_modifiers=[
                {"field": "cc", "match_type": "exact", "value": "FR", "delta": 10}
            ],
        )
        row = _make_row(asn="16276", cc="FR")
        score = calculate_confidence(fp, row)
        assert score == 80

    def test_negative_delta_applied(self):
        fp = _make_fp(
            confidence_base=70,
            confidence_modifiers=[
                {"field": "cc", "match_type": "exact", "value": "US", "delta": -20}
            ],
        )
        row = _make_row(asn="16276", cc="US")
        score = calculate_confidence(fp, row)
        assert score == 50

    def test_confidence_clamped_to_100(self):
        fp = _make_fp(
            confidence_base=95,
            confidence_modifiers=[
                {"field": "cc", "match_type": "exact", "value": "FR", "delta": 10},
                {"field": "asn", "match_type": "exact", "value": "16276", "delta": 15},
            ],
        )
        row = _make_row(asn="16276", cc="FR")
        score = calculate_confidence(fp, row)
        assert score == 100

    def test_confidence_clamped_to_zero(self):
        fp = _make_fp(
            confidence_base=10,
            confidence_modifiers=[
                {"field": "cc", "match_type": "exact", "value": "US", "delta": -30}
            ],
        )
        row = _make_row(asn="16276", cc="US")
        score = calculate_confidence(fp, row)
        assert score == 0


# ============================================================
# Integration / Evaluate Logic (5 tests)
# ============================================================

class TestEvaluateFingerprint:

    def test_all_required_pass_returns_match(self):
        fp = _make_fp(indicators=[
            {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
            {"field": "ns", "match_type": "contains", "value": "cprapid.com", "required": True},
        ])
        row = _make_row(asn="16276", nameservers="ns1.cprapid.com;ns2.cprapid.com")
        result = evaluate_fingerprint(fp, row)
        assert result is not None
        assert result["fp_id"] == "FP-TEST"

    def test_required_indicator_fails_returns_none(self):
        fp = _make_fp(indicators=[
            {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
        ])
        row = _make_row(asn="99999")
        result = evaluate_fingerprint(fp, row)
        assert result is None

    def test_non_required_failure_still_matches(self):
        fp = _make_fp(indicators=[
            {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
            {"field": "mx", "match_type": "contains", "value": "temp-mail.com", "required": False},
        ])
        row = _make_row(asn="16276", primary_mx="other-mx.com")
        result = evaluate_fingerprint(fp, row)
        assert result is not None

    def test_empty_field_treated_as_no_match(self):
        fp = _make_fp(indicators=[
            {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
        ])
        row = _make_row(asn="")
        result = evaluate_fingerprint(fp, row)
        assert result is None

    def test_missing_field_treated_as_no_match(self):
        fp = _make_fp(indicators=[
            {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
        ])
        row = _make_row()
        del row["asn"]
        result = evaluate_fingerprint(fp, row)
        assert result is None


class TestMatchDomain:

    def test_domain_matches_multiple_fingerprints(self):
        fp1 = _make_fp(id="FP-A", indicators=[
            {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
        ])
        fp2 = _make_fp(id="FP-B", indicators=[
            {"field": "ns", "match_type": "contains", "value": "cprapid.com", "required": True},
        ])
        row = _make_row(asn="16276", nameservers="ns1.cprapid.com")
        results = match_domain(row, [fp1, fp2])
        assert len(results) == 2
        ids = {r["fp_id"] for r in results}
        assert ids == {"FP-A", "FP-B"}

    def test_domain_matches_zero_fingerprints(self):
        fp = _make_fp(indicators=[
            {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
        ])
        row = _make_row(asn="99999")
        results = match_domain(row, [fp])
        assert len(results) == 0
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_fingerprints.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'match_fingerprints'`

**Step 3: Write the matching engine implementation**

Create `scripts/match_fingerprints.py`:

```python
#!/usr/bin/env python3
"""
match_fingerprints.py

Infrastructure Fingerprinting Engine.
Loads YAML fingerprint definitions from config/fingerprints/ and evaluates
each domain row from the enriched pipeline CSV against all fingerprints.
Outputs confidence-scored matches to data/fingerprint_matches.csv.
"""

import argparse
import csv
import glob
import logging
import os
import re
from typing import Any, Dict, List, Optional

import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Configuration ---

FINGERPRINT_DIR = "config/fingerprints"
DEFAULT_INPUT = "data/dea_domains_probed.csv"
DEFAULT_OUTPUT = "data/fingerprint_matches.csv"
OUTPUT_FIELDS = ["domain", "fp_id", "fp_name", "confidence", "flame_tp_ids", "evidence"]

FIELD_ALIASES = {
    "ns": "nameservers",
    "mx": "primary_mx",
    "registrar": "registry",
    "country": "cc",
    "title": "http_title",
}

VALID_MATCH_TYPES = {"exact", "contains", "regex", "range"}

REQUIRED_FP_KEYS = {"id", "name", "indicators", "confidence_base"}
REQUIRED_INDICATOR_KEYS = {"field", "match_type", "value"}


# --- Core Functions ---

def resolve_field(field: str) -> str:
    """Resolve a field alias to its CSV column name."""
    return FIELD_ALIASES.get(field, field)


def validate_fingerprint(fp: Dict[str, Any], source: str = "unknown") -> Dict[str, Any]:
    """Validate a fingerprint dict has all required keys and valid match types.

    Args:
        fp: Parsed fingerprint dict from YAML.
        source: Filename for error messages.

    Returns:
        The validated fingerprint dict (unchanged).

    Raises:
        ValueError: If required keys are missing or match_type is invalid.
    """
    for key in REQUIRED_FP_KEYS:
        if key not in fp:
            raise ValueError(f"Fingerprint from {source} missing required key: {key}")

    for i, ind in enumerate(fp.get("indicators", [])):
        for key in REQUIRED_INDICATOR_KEYS:
            if key not in ind:
                raise ValueError(
                    f"Fingerprint {fp.get('id', '?')} indicator {i} missing key: {key}"
                )
        mt = ind["match_type"]
        if mt not in VALID_MATCH_TYPES:
            raise ValueError(
                f"Fingerprint {fp.get('id', '?')} indicator {i} has invalid match_type: {mt}"
            )
        # Pre-validate regex patterns at load time
        if mt == "regex":
            try:
                re.compile(ind["value"])
            except re.error as e:
                raise ValueError(
                    f"Fingerprint {fp.get('id', '?')} indicator {i} has invalid regex: {e}"
                )

    # Defaults for optional keys
    fp.setdefault("confidence_modifiers", [])
    fp.setdefault("flame_tp_ids", [])
    fp.setdefault("ttl_days", 30)
    fp.setdefault("description", "")
    fp.setdefault("version", 1)

    return fp


def check_indicator(field_data: str, match_type: str, value: str) -> bool:
    """Check whether a single indicator condition matches a field value.

    Args:
        field_data: The actual value from the domain CSV row.
        match_type: One of exact, contains, regex, range.
        value: The pattern/value from the fingerprint indicator.

    Returns:
        True if the indicator matches.
    """
    if not field_data:
        return False

    if match_type == "exact":
        return field_data.strip().lower() == value.strip().lower()

    if match_type == "contains":
        return value.strip().lower() in field_data.strip().lower()

    if match_type == "regex":
        return bool(re.search(value, field_data, re.IGNORECASE))

    if match_type == "range":
        try:
            low_s, high_s = value.split("-", 1)
            low, high = int(low_s), int(high_s)
            num = int(field_data.strip())
            return low <= num <= high
        except (ValueError, TypeError):
            return False

    return False


def calculate_confidence(fp: Dict[str, Any], row: Dict[str, str]) -> int:
    """Calculate the final confidence score for a fingerprint match.

    Args:
        fp: The fingerprint dict.
        row: The domain CSV row dict.

    Returns:
        Confidence score clamped to 0-100.
    """
    score = fp["confidence_base"]
    for mod in fp.get("confidence_modifiers", []):
        col = resolve_field(mod.get("field", ""))
        field_data = row.get(col, "")
        if check_indicator(field_data, mod.get("match_type", "exact"), mod.get("value", "")):
            score += mod.get("delta", 0)
    return max(0, min(100, score))


def evaluate_fingerprint(fp: Dict[str, Any], row: Dict[str, str]) -> Optional[Dict[str, str]]:
    """Evaluate a single fingerprint against a single domain row.

    Args:
        fp: Validated fingerprint dict.
        row: Domain CSV row dict.

    Returns:
        Match result dict or None if no match.
    """
    evidence_parts = []

    # Check all required indicators (AND logic)
    for ind in fp["indicators"]:
        col = resolve_field(ind["field"])
        field_data = row.get(col, "")
        matched = check_indicator(field_data, ind["match_type"], ind["value"])

        if matched:
            sep = "=" if ind["match_type"] == "exact" else "~"
            evidence_parts.append(f"{col}{sep}{ind['value']}")

        if ind.get("required", True) and not matched:
            return None

    confidence = calculate_confidence(fp, row)
    tp_ids = ",".join(fp.get("flame_tp_ids", []))

    return {
        "domain": row.get("domain", ""),
        "fp_id": fp["id"],
        "fp_name": fp["name"],
        "confidence": str(confidence),
        "flame_tp_ids": tp_ids,
        "evidence": ";".join(evidence_parts),
    }


def match_domain(row: Dict[str, str], fingerprints: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Match a single domain row against all loaded fingerprints.

    Returns:
        List of match result dicts (may be empty).
    """
    results = []
    for fp in fingerprints:
        result = evaluate_fingerprint(fp, row)
        if result:
            results.append(result)
    return results


# --- Loading ---

def load_fingerprints_from_list(fp_dicts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Validate and sort a list of fingerprint dicts.

    Used by tests to load fingerprints without touching the filesystem.
    """
    validated = []
    for fp in fp_dicts:
        validated.append(validate_fingerprint(fp, source="list"))
    validated.sort(key=lambda f: f["id"])
    return validated


def load_fingerprints(directory: str = FINGERPRINT_DIR) -> List[Dict[str, Any]]:
    """Load all YAML fingerprint files from a directory.

    Args:
        directory: Path to the fingerprints directory.

    Returns:
        Sorted list of validated fingerprint dicts.
    """
    pattern = os.path.join(directory, "*.yaml")
    files = sorted(glob.glob(pattern))
    if not files:
        logger.warning("No fingerprint files found in %s", directory)
        return []

    fingerprints = []
    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                fp = yaml.safe_load(f)
            if not fp:
                logger.warning("Empty fingerprint file: %s", filepath)
                continue
            validated = validate_fingerprint(fp, source=os.path.basename(filepath))
            fingerprints.append(validated)
            logger.info("Loaded fingerprint: %s (%s)", validated["id"], validated["name"])
        except (yaml.YAMLError, ValueError, OSError) as e:
            logger.error("Failed to load fingerprint %s: %s", filepath, e)
            continue

    fingerprints.sort(key=lambda f: f["id"])
    logger.info("Loaded %d fingerprints total", len(fingerprints))
    return fingerprints


# --- Main ---

def run(input_file: str, output_file: str, fp_dir: str = FINGERPRINT_DIR) -> int:
    """Run the fingerprint matching engine.

    Returns:
        Number of matches found.
    """
    fingerprints = load_fingerprints(fp_dir)
    if not fingerprints:
        logger.warning("No fingerprints loaded. Nothing to match.")
        return 0

    if not os.path.exists(input_file):
        logger.error("Input file not found: %s", input_file)
        return 0

    all_matches = []

    with open(input_file, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            matches = match_domain(row, fingerprints)
            all_matches.extend(matches)

    if all_matches:
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS)
            writer.writeheader()
            writer.writerows(all_matches)
        logger.info("Wrote %d matches to %s", len(all_matches), output_file)
    else:
        logger.info("No fingerprint matches found.")

    return len(all_matches)


def main():
    parser = argparse.ArgumentParser(description="Infrastructure Fingerprint Matcher")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Input CSV file")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output CSV file")
    parser.add_argument("--fingerprints", default=FINGERPRINT_DIR, help="Fingerprints directory")
    args = parser.parse_args()

    count = run(args.input, args.output, args.fingerprints)
    logger.info("Done. %d total matches.", count)


if __name__ == "__main__":
    main()
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_fingerprints.py -v`
Expected: 19 passed

**Step 5: Commit**

```bash
git add tests/test_fingerprints.py scripts/match_fingerprints.py
git commit -m "feat: add infrastructure fingerprint matching engine with tests"
```

---

### Task 2: Create Reference Fingerprint (FP-0001)

**Files:**
- Create: `config/fingerprints/FP-0001-ovh-cpanel-dea.yaml`

**Step 1: Create the YAML file**

```yaml
id: "FP-0001"
name: "OVH cPanel DEA Infrastructure"
description: >
  Bulk disposable-email-address domains hosted on OVH (ASN 16276)
  using cprapid.com nameservers and temp-mail-pro.com MX.
  Common pattern for throwaway fraud infrastructure.
version: 1

indicators:
  - field: asn
    match_type: exact
    value: "16276"
    required: true

  - field: ns
    match_type: contains
    value: "cprapid.com"
    required: true

  - field: mx
    match_type: contains
    value: "temp-mail-pro.com"
    required: false

confidence_base: 70

confidence_modifiers:
  - field: mx
    match_type: contains
    value: "temp-mail-pro.com"
    delta: 15

  - field: cc
    match_type: exact
    value: "FR"
    delta: 10

flame_tp_ids:
  - "TP-0003"

ttl_days: 30
```

**Step 2: Verify it loads cleanly**

Run: `python -c "import yaml; fp=yaml.safe_load(open('config/fingerprints/FP-0001-ovh-cpanel-dea.yaml')); print(fp['id'], fp['name'])"`
Expected: `FP-0001 OVH cPanel DEA Infrastructure`

**Step 3: Commit**

```bash
git add config/fingerprints/FP-0001-ovh-cpanel-dea.yaml
git commit -m "feat: add FP-0001 OVH cPanel DEA fingerprint"
```

---

### Task 3: Create Remaining 6 Fingerprints (FP-0002 through FP-0007)

**Files:**
- Create: `config/fingerprints/FP-0002-alibaba-sideloading.yaml`
- Create: `config/fingerprints/FP-0003-crypto-finance-cohosting.yaml`
- Create: `config/fingerprints/FP-0004-gname-cloudflare-china.yaml`
- Create: `config/fingerprints/FP-0005-godaddy-bulk-registration.yaml`
- Create: `config/fingerprints/FP-0006-shell-domain-mx-cluster.yaml`
- Create: `config/fingerprints/FP-0007-typosquat-evasion-infra.yaml`

Create each YAML following the FP-0001 schema. See the design doc table for indicator details:

| ID | Required Indicators | Modifiers | Base Conf | FLAME TP |
|---|---|---|---|---|
| FP-0002 | ASN 45102 (exact) + http_title regex `(download\|install\|apk\|sideload)` | mx contains DEA provider (+10) | 65 | TP-0012 |
| FP-0003 | http_title regex `(crypto\|bitcoin\|wallet\|defi\|trading\|forex)` + mx contains DEA provider | asn range for common shared hosting (+10) | 60 | TP-0017 |
| FP-0004 | registry contains "Gname" + ns contains "cloudflare" | cc exact "CN" (+15), asn range 45000-45999 (+10) | 65 | TP-0017 |
| FP-0005 | registry contains "GoDaddy" | risk_tags contains "bulk" (+15) | 55 | TP-0019 |
| FP-0006 | mx_records regex (non-standard shared MX pattern) + http_status exact "0" or empty | age_days range 0-90 (+15) | 60 | TP-0003 |
| FP-0007 | risk_tags contains "typosquat" + http_status regex `^3\d\d$` + primary_mx not empty | — | 75 | TP-0012 |

**Step 1: Create all 6 YAML files**

**Step 2: Validate all load cleanly**

Run: `python -c "from scripts.match_fingerprints import load_fingerprints; fps=load_fingerprints(); print(f'{len(fps)} fingerprints loaded')"`
Expected: `7 fingerprints loaded`

**Step 3: Commit**

```bash
git add config/fingerprints/
git commit -m "feat: add FP-0002 through FP-0007 fingerprint definitions"
```

---

### Task 4: Pipeline Integration

**Files:**
- Modify: `scripts/triage_domains.py:30-35` (add constant), `:81-99` (add loader), `:186-204` (add priority check)
- Modify: `.github/workflows/update_intelligence.yml:218-223` (add workflow step)

**Step 1: Add fingerprint match loading to triage_domains.py**

At the top constants section (around line 35), add:

```python
FINGERPRINT_MATCHES_FILE = "data/fingerprint_matches.csv"
```

Add a new function after `load_flame_tp_ids()` (after line 99):

```python
def load_fingerprint_matches() -> Dict[str, Dict[str, str]]:
    """Load fingerprint match results keyed by domain.

    If a domain has multiple matches, keeps the highest-confidence one.

    Returns:
        Dict mapping domain -> {fp_id, fp_name, confidence, flame_tp_ids, evidence}.
    """
    matches: Dict[str, Dict[str, str]] = {}
    if not os.path.exists(FINGERPRINT_MATCHES_FILE):
        return matches
    try:
        with open(FINGERPRINT_MATCHES_FILE, "r", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain = row.get("domain", "").strip().lower()
                confidence = int(row.get("confidence", "0"))
                existing = matches.get(domain)
                if not existing or confidence > int(existing.get("confidence", "0")):
                    matches[domain] = row
    except (IOError, csv.Error, ValueError) as exc:
        logger.warning("Could not load fingerprint matches: %s", exc)
    return matches
```

In `main()`, after loading `flame_rules` (line 176), add:

```python
    fp_matches = load_fingerprint_matches()
    if fp_matches:
        print(f"    - Fingerprint matches: {len(fp_matches)}")
```

In the triage loop (around line 189-204), add a new priority block BEFORE the FLAME TP check:

```python
        # Priority 0: Infrastructure Fingerprint match (highest)
        if not reason and d in fp_matches:
            m = fp_matches[d]
            fp_id = m.get("fp_id", "")
            fp_name = m.get("fp_name", "")
            conf = m.get("confidence", "0")
            reason = f"{fp_id}: {fp_name} (conf: {conf})"
            priority = 0
            # Merge FLAME TP IDs from fingerprint if not already set
            if not flame_tp_ids:
                flame_tp_ids = m.get("flame_tp_ids", "")
```

**Step 2: Add workflow step to update_intelligence.yml**

Insert a new step after "Data Hygiene & Enrichment" (after line 222) and before "Build Investigate Index":

```yaml
      - name: Infrastructure Fingerprinting
        run: python scripts/match_fingerprints.py
```

**Step 3: Run triage_domains.py with --limit 10 to smoke-test**

Run: `python scripts/triage_domains.py --limit 10`
Expected: Runs without error. May print `- Fingerprint matches: 0` if no matches file exists yet.

**Step 4: Commit**

```bash
git add scripts/triage_domains.py .github/workflows/update_intelligence.yml
git commit -m "feat: integrate fingerprint engine into triage pipeline and CI workflow"
```

---

### Task 5: Full Integration Test

**Step 1: Run the matching engine against real data (if available)**

Run: `python scripts/match_fingerprints.py --input data/dea_domains_probed.csv --output data/fingerprint_matches.csv`

If `dea_domains_probed.csv` doesn't exist locally, create a small test CSV:

```bash
echo "domain,asn,nameservers,primary_mx,registry,cc,http_title,http_status,risk_tags,mx_records,age_days" > /tmp/test_probed.csv
echo "evil-test.com,16276,ns1.cprapid.com;ns2.cprapid.com,mail.temp-mail-pro.com,OVH,FR,Login Page,200,,mail.temp-mail-pro.com,10" >> /tmp/test_probed.csv
echo "clean-site.com,13335,ns1.cloudflare.com,mx.google.com,Cloudflare,US,Welcome,200,,mx.google.com,365" >> /tmp/test_probed.csv
python scripts/match_fingerprints.py --input /tmp/test_probed.csv --output /tmp/test_fp_matches.csv
cat /tmp/test_fp_matches.csv
```

Expected: `evil-test.com` matches FP-0001 with confidence ~95 (70 base + 15 MX + 10 FR). `clean-site.com` matches nothing.

**Step 2: Run full test suite**

Run: `pytest tests/ -v`
Expected: All tests pass including new fingerprint tests.

**Step 3: Commit any final adjustments**

```bash
git add -A
git commit -m "test: verify fingerprint engine end-to-end integration"
```
