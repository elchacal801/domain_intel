#!/usr/bin/env python3
"""
tests/test_virustotal.py

Unit tests for the VirusTotal enrichment module.
"""

import os
import sys
import time

import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from enrich_virustotal import (
    parse_vt_response,
    query_virustotal,
    RateLimiter,
    VT_COLUMNS,
    EMPTY_RESULT,
)

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_VT_RESPONSE = {
    "data": {
        "id": "evil-example.com",
        "type": "domain",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 5,
                "suspicious": 2,
                "undetected": 70,
                "harmless": 10,
                "timeout": 0,
            },
            "reputation": -42,
            "last_analysis_date": 1740000000,
        },
    }
}


# ---------------------------------------------------------------------------
# TestParseVtResponse
# ---------------------------------------------------------------------------

class TestParseVtResponse:

    def test_parses_malicious_domain(self):
        """Full VT response is parsed into expected columns."""
        result = parse_vt_response(SAMPLE_VT_RESPONSE)
        assert result["vt_malicious_count"] == "5"
        assert result["vt_total_engines"] == "87"
        assert result["vt_reputation"] == "-42"
        assert result["vt_last_analysis_date"] != ""

    def test_handles_missing_fields(self):
        """Partial response with missing attributes returns safe defaults."""
        partial = {"data": {"attributes": {}}}
        result = parse_vt_response(partial)
        assert result["vt_malicious_count"] == "0"
        assert result["vt_total_engines"] == "0"
        assert result["vt_reputation"] == ""
        assert result["vt_last_analysis_date"] == ""


# ---------------------------------------------------------------------------
# TestRateLimiter
# ---------------------------------------------------------------------------

class TestRateLimiter:

    def test_enforces_interval(self):
        """Two consecutive wait() calls on a 60 RPM limiter should take ~1s."""
        limiter = RateLimiter(requests_per_minute=60)
        start = time.time()
        limiter.wait()
        limiter.wait()
        elapsed = time.time() - start
        assert elapsed >= 0.9, f"Expected >= 0.9s, got {elapsed:.2f}s"


# ---------------------------------------------------------------------------
# TestBudgetEnforcement
# ---------------------------------------------------------------------------

class TestBudgetEnforcement:

    def test_budget_exhausted_returns_empty(self):
        """When budget is exhausted, query returns EMPTY_RESULT."""
        mock_cache = MagicMock()
        mock_cache.get.return_value = None

        mock_budget = MagicMock()
        mock_budget.check_can_spend.return_value = False

        mock_limiter = MagicMock()

        result = query_virustotal(
            "example.com", "fake-key", mock_cache, mock_budget, mock_limiter
        )
        assert result == EMPTY_RESULT

    @patch("enrich_virustotal._vt_api_get")
    def test_budget_tracks_spend(self, mock_get):
        """Successful API call should call budget.spend(1)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_VT_RESPONSE
        mock_get.return_value = mock_resp

        mock_cache = MagicMock()
        mock_cache.get.return_value = None

        mock_budget = MagicMock()
        mock_budget.check_can_spend.return_value = True

        mock_limiter = MagicMock()

        query_virustotal(
            "example.com", "fake-key", mock_cache, mock_budget, mock_limiter
        )
        mock_budget.spend.assert_called_once_with(1)


# ---------------------------------------------------------------------------
# TestCacheBehavior
# ---------------------------------------------------------------------------

class TestCacheBehavior:

    @patch("enrich_virustotal.requests.get")
    def test_cache_hit_skips_api(self, mock_get):
        """When cache returns data, requests.get should NOT be called."""
        cached_data = {
            "vt_malicious_count": "3",
            "vt_total_engines": "80",
            "vt_reputation": "-10",
            "vt_last_analysis_date": "2025-01-01",
        }
        mock_cache = MagicMock()
        mock_cache.get.return_value = cached_data

        mock_budget = MagicMock()
        mock_limiter = MagicMock()

        result = query_virustotal(
            "example.com", "fake-key", mock_cache, mock_budget, mock_limiter
        )
        assert result == cached_data
        mock_get.assert_not_called()

    @patch("enrich_virustotal._vt_api_get")
    def test_cache_miss_stores_result(self, mock_get):
        """Cache miss + successful API call should store result in cache."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_VT_RESPONSE
        mock_get.return_value = mock_resp

        mock_cache = MagicMock()
        mock_cache.get.return_value = None

        mock_budget = MagicMock()
        mock_budget.check_can_spend.return_value = True

        mock_limiter = MagicMock()

        query_virustotal(
            "example.com", "fake-key", mock_cache, mock_budget, mock_limiter
        )
        mock_cache.set.assert_called_once()


# ---------------------------------------------------------------------------
# TestErrorHandling
# ---------------------------------------------------------------------------

class TestErrorHandling:

    @patch("enrich_virustotal._vt_api_get")
    def test_404_caches_empty(self, mock_get):
        """404 response should cache EMPTY_RESULT."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        mock_cache = MagicMock()
        mock_cache.get.return_value = None

        mock_budget = MagicMock()
        mock_budget.check_can_spend.return_value = True

        mock_limiter = MagicMock()

        result = query_virustotal(
            "example.com", "fake-key", mock_cache, mock_budget, mock_limiter
        )
        assert result == EMPTY_RESULT
        mock_cache.set.assert_called_once()

    @patch("enrich_virustotal._vt_api_get")
    def test_401_returns_empty_no_cache(self, mock_get):
        """401 response should return EMPTY_RESULT without caching."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp

        mock_cache = MagicMock()
        mock_cache.get.return_value = None

        mock_budget = MagicMock()
        mock_budget.check_can_spend.return_value = True

        mock_limiter = MagicMock()

        result = query_virustotal(
            "example.com", "fake-key", mock_cache, mock_budget, mock_limiter
        )
        assert result == EMPTY_RESULT
        mock_cache.set.assert_not_called()


# ---------------------------------------------------------------------------
# TestFingerprintModifiers
# ---------------------------------------------------------------------------

class TestFingerprintModifiers:

    def test_vt_malicious_count_applies_delta(self):
        """vt_malicious_count in range 3-100 should apply +20 delta."""
        from match_fingerprints import calculate_confidence, validate_fingerprint

        fp = {
            "id": "FP-TEST",
            "name": "Test",
            "description": "",
            "version": 1,
            "indicators": [
                {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
            ],
            "confidence_base": 60,
            "confidence_modifiers": [
                {"field": "vt_malicious_count", "match_type": "range", "value": "3-100", "delta": 20},
            ],
            "flame_tp_ids": [],
            "ttl_days": 30,
        }
        fp = validate_fingerprint(fp, source="test")
        row = {"asn": "16276", "vt_malicious_count": "5"}
        assert calculate_confidence(fp, row) == 80
