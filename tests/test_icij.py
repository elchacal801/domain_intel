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
# Org Name Extraction (2 tests)
# ============================================================

class TestGetOrgName:

    def test_prefers_registrant_org(self):
        row = {"registrant_org": "Acme Corp", "ssl_org": "Cloudflare"}
        assert get_org_name(row) == "Acme Corp"

    def test_falls_back_to_ssl_org(self):
        row = {"registrant_org": "", "ssl_org": "Google LLC"}
        assert get_org_name(row) == "Google LLC"


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
        assert int(result["icij_match_score"]) == 100
        assert result["icij_entity_match"] == "True"

    def test_close_match_above_threshold(self):
        entries = parse_icij_nodes_csv(
            io.StringIO(SAMPLE_ENTITIES_CSV), node_type="Entity"
        )
        result = fuzzy_match_org("Acme Offshore Holding", entries)
        assert result is not None
        assert int(result["icij_match_score"]) >= MATCH_THRESHOLD

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
