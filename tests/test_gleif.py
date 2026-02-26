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
