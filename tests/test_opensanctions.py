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
        assert int(result["os_match_score"]) == 100
        assert result["os_entity_id"] == "NK-001"

    def test_close_match_above_threshold(self):
        """A close-enough name should match above threshold."""
        entries = parse_opensanctions_csv(io.StringIO(SAMPLE_CSV))
        result = fuzzy_match_org("Acme Holdings", entries)
        assert result is not None
        assert int(result["os_match_score"]) >= MATCH_THRESHOLD

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
        mock_resp.iter_content.return_value = [
            SAMPLE_CSV.strip().encode("utf-8")
        ]
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("enrich_opensanctions.requests.get", return_value=mock_resp):
            from enrich_opensanctions import download_and_parse
            entries = download_and_parse(cache_dir=tempfile.mkdtemp())

        assert len(entries) > 0
        names = [e["name"] for e in entries]
        assert "apple inc." in names


class TestFingerprintModifiers:

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
