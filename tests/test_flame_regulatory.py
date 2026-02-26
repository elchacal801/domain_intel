#!/usr/bin/env python3
"""Tests for regulatory alerts functionality in shared.flame_client."""

import json
import os
import sys
import time

import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from shared import flame_client


# Sample regulatory alerts data for mocking
SAMPLE_ALERTS = [
    {
        "id": "RA-2026-001",
        "title": "FinCEN Advisory on Phishing Campaigns Targeting ACH",
        "source": "fincen",
        "severity": "high",
        "mapped_tp_ids": ["TP-0001", "TP-0003"],
        "published": "2026-02-20",
    },
    {
        "id": "RA-2026-002",
        "title": "OCC Bulletin on BEC Wire Fraud Trends",
        "source": "occ",
        "severity": "medium",
        "mapped_tp_ids": ["TP-0002"],
        "published": "2026-02-18",
    },
    {
        "id": "RA-2026-003",
        "title": "CFPB Report on Account Takeover via Social Engineering",
        "source": "cfpb",
        "severity": "low",
        "mapped_tp_ids": ["TP-0001"],
        "published": "2026-02-15",
    },
]


class TestRegulatoryUrl:
    """Test the regulatory URL config resolution."""

    def test_default_url(self):
        url = flame_client._regulatory_url()
        assert "regulatory-alerts.json" in url
        assert "elchacal801.github.io" in url

    @patch("shared.flame_client.cfg.get")
    def test_custom_url_from_config(self, mock_cfg):
        mock_cfg.return_value = "https://custom.example.com/alerts.json"
        url = flame_client._regulatory_url()
        assert url == "https://custom.example.com/alerts.json"


class TestFetchRegulatoryAlerts:
    """Test network fetching of regulatory-alerts.json."""

    @patch("shared.flame_client.requests.get")
    def test_successful_fetch(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_ALERTS
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = flame_client._fetch_regulatory()
        assert result is not None
        assert len(result) == 3
        assert result[0]["id"] == "RA-2026-001"

    @patch("shared.flame_client.requests.get")
    def test_network_failure_returns_none(self, mock_get):
        import requests
        mock_get.side_effect = requests.ConnectionError("timeout")

        result = flame_client._fetch_regulatory()
        assert result is None

    @patch("shared.flame_client.requests.get")
    def test_non_list_response_returns_none(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"not": "a list"}
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = flame_client._fetch_regulatory()
        assert result is None

    @patch("shared.flame_client.requests.get")
    def test_invalid_json_returns_none(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("bad json")
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = flame_client._fetch_regulatory()
        assert result is None


class TestRegulatoryCacheOperations:
    """Test regulatory cache read/write logic."""

    def test_save_and_load_reg_cache(self, tmp_path):
        cache_file = tmp_path / "regulatory-alerts.json"
        meta_file = tmp_path / ".reg_meta.json"

        with patch.object(flame_client, '_REG_CACHE_FILE', cache_file), \
             patch.object(flame_client, '_REG_CACHE_META', meta_file), \
             patch.object(flame_client, '_CACHE_DIR', tmp_path):

            flame_client._save_reg_cache(SAMPLE_ALERTS)

            assert cache_file.exists()
            assert meta_file.exists()

            loaded = flame_client._load_reg_cache()
            assert loaded is not None
            assert len(loaded) == 3
            assert loaded[0]["id"] == "RA-2026-001"

    def test_stale_reg_cache_returns_none(self, tmp_path):
        cache_file = tmp_path / "regulatory-alerts.json"
        meta_file = tmp_path / ".reg_meta.json"

        with patch.object(flame_client, '_REG_CACHE_FILE', cache_file), \
             patch.object(flame_client, '_REG_CACHE_META', meta_file), \
             patch.object(flame_client, '_CACHE_DIR', tmp_path):

            flame_client._save_reg_cache(SAMPLE_ALERTS)
            # Overwrite meta with old timestamp
            with open(meta_file, "w") as f:
                json.dump({"fetched_at": time.time() - 100_000}, f)

            loaded = flame_client._load_reg_cache()
            assert loaded is None

    def test_missing_reg_cache_returns_none(self, tmp_path):
        cache_file = tmp_path / "nonexistent.json"
        meta_file = tmp_path / "nonexistent_meta.json"

        with patch.object(flame_client, '_REG_CACHE_FILE', cache_file), \
             patch.object(flame_client, '_REG_CACHE_META', meta_file):

            loaded = flame_client._load_reg_cache()
            assert loaded is None


class TestGetRegulatoryAlerts:
    """Test the main get_regulatory_alerts() public function."""

    @patch("shared.flame_client._fetch_regulatory")
    @patch("shared.flame_client._load_reg_cache")
    def test_cache_hit_no_network(self, mock_cache, mock_fetch):
        mock_cache.return_value = SAMPLE_ALERTS
        result = flame_client.get_regulatory_alerts()

        assert len(result) == 3
        mock_fetch.assert_not_called()

    @patch("shared.flame_client._save_reg_cache")
    @patch("shared.flame_client._fetch_regulatory")
    @patch("shared.flame_client._load_reg_cache")
    def test_cache_miss_triggers_fetch(self, mock_cache, mock_fetch, mock_save):
        mock_cache.return_value = None
        mock_fetch.return_value = SAMPLE_ALERTS

        result = flame_client.get_regulatory_alerts()
        assert len(result) == 3
        mock_fetch.assert_called_once()
        mock_save.assert_called_once()

    @patch("shared.flame_client._force_reg_cache_fallback")
    @patch("shared.flame_client._fetch_regulatory")
    @patch("shared.flame_client._load_reg_cache")
    def test_both_fail_returns_stale_or_empty(self, mock_cache, mock_fetch, mock_fallback):
        mock_cache.return_value = None
        mock_fetch.return_value = None
        mock_fallback.return_value = []

        result = flame_client.get_regulatory_alerts()
        assert result == []
        mock_fallback.assert_called_once()

    @patch("shared.flame_client._force_reg_cache_fallback")
    @patch("shared.flame_client._fetch_regulatory")
    @patch("shared.flame_client._load_reg_cache")
    def test_stale_fallback_returns_data(self, mock_cache, mock_fetch, mock_fallback):
        mock_cache.return_value = None
        mock_fetch.return_value = None
        mock_fallback.return_value = SAMPLE_ALERTS

        result = flame_client.get_regulatory_alerts()
        assert len(result) == 3
        assert result[0]["id"] == "RA-2026-001"

    def test_force_reg_cache_fallback_with_data(self, tmp_path):
        cache_file = tmp_path / "regulatory-alerts.json"
        with open(cache_file, "w") as f:
            json.dump(SAMPLE_ALERTS, f)

        with patch.object(flame_client, '_REG_CACHE_FILE', cache_file):
            result = flame_client._force_reg_cache_fallback()
            assert len(result) == 3

    def test_force_reg_cache_fallback_no_file(self, tmp_path):
        cache_file = tmp_path / "nonexistent.json"

        with patch.object(flame_client, '_REG_CACHE_FILE', cache_file):
            result = flame_client._force_reg_cache_fallback()
            assert result == []

    @patch("shared.flame_client.requests.get")
    def test_end_to_end_network_success(self, mock_get, tmp_path):
        """Full integration: empty cache -> network fetch -> return data."""
        cache_file = tmp_path / "regulatory-alerts.json"
        meta_file = tmp_path / ".reg_meta.json"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_ALERTS
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        with patch.object(flame_client, '_REG_CACHE_FILE', cache_file), \
             patch.object(flame_client, '_REG_CACHE_META', meta_file), \
             patch.object(flame_client, '_CACHE_DIR', tmp_path):

            result = flame_client.get_regulatory_alerts()
            assert len(result) == 3
            assert cache_file.exists()
            assert meta_file.exists()

    @patch("shared.flame_client.requests.get")
    def test_end_to_end_network_failure_empty(self, mock_get, tmp_path):
        """Full integration: empty cache -> network fails -> return []."""
        import requests
        cache_file = tmp_path / "nonexistent.json"
        meta_file = tmp_path / "nonexistent_meta.json"

        mock_get.side_effect = requests.ConnectionError("no network")

        with patch.object(flame_client, '_REG_CACHE_FILE', cache_file), \
             patch.object(flame_client, '_REG_CACHE_META', meta_file), \
             patch.object(flame_client, '_CACHE_DIR', tmp_path):

            result = flame_client.get_regulatory_alerts()
            assert result == []
