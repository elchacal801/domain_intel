#!/usr/bin/env python3
"""Tests for shared.flame_client module."""

import json
import os
import sys
import time
import tempfile

import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from shared import flame_client


# Sample FLAME index data for mocking
SAMPLE_INDEX = [
    {
        "id": "TP-0001",
        "title": "Treasury Management ATO via Malvertising and Vishing",
        "summary": "Threat actors target commercial banking customers using a multi-phase scheme.",
        "fraud_types": ["account-takeover", "vishing"],
    },
    {
        "id": "TP-0002",
        "title": "Business Email Compromise",
        "summary": "Threat actors compromise vendor email accounts.",
        "fraud_types": ["BEC", "wire-fraud"],
    },
]


class TestFetchIndex:
    """Test network fetching of flame-index.json."""

    @patch("shared.flame_client.requests.get")
    def test_successful_fetch(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_INDEX
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = flame_client._fetch_index()
        assert result is not None
        assert len(result) == 2
        assert result[0]["id"] == "TP-0001"

    @patch("shared.flame_client.requests.get")
    def test_network_failure_returns_none(self, mock_get):
        import requests
        mock_get.side_effect = requests.ConnectionError("timeout")

        result = flame_client._fetch_index()
        assert result is None

    @patch("shared.flame_client.requests.get")
    def test_non_list_response_returns_none(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"not": "a list"}
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = flame_client._fetch_index()
        assert result is None


class TestCache:
    """Test local cache read/write logic."""

    def test_save_and_load_cache(self, tmp_path):
        cache_file = tmp_path / "index.json"
        meta_file = tmp_path / ".meta.json"

        with patch.object(flame_client, '_CACHE_FILE', cache_file), \
             patch.object(flame_client, '_CACHE_META', meta_file), \
             patch.object(flame_client, '_CACHE_DIR', tmp_path):

            flame_client._save_cache(SAMPLE_INDEX)

            assert cache_file.exists()
            assert meta_file.exists()

            loaded = flame_client._load_cache()
            assert loaded is not None
            assert len(loaded) == 2
            assert loaded[0]["id"] == "TP-0001"

    def test_stale_cache_returns_none(self, tmp_path):
        cache_file = tmp_path / "index.json"
        meta_file = tmp_path / ".meta.json"

        with patch.object(flame_client, '_CACHE_FILE', cache_file), \
             patch.object(flame_client, '_CACHE_META', meta_file), \
             patch.object(flame_client, '_CACHE_DIR', tmp_path):

            # Write cache with old timestamp
            flame_client._save_cache(SAMPLE_INDEX)
            with open(meta_file, "w") as f:
                json.dump({"fetched_at": time.time() - 100_000}, f)

            loaded = flame_client._load_cache()
            assert loaded is None

    def test_missing_cache_returns_none(self, tmp_path):
        cache_file = tmp_path / "nonexistent.json"
        meta_file = tmp_path / "nonexistent_meta.json"

        with patch.object(flame_client, '_CACHE_FILE', cache_file), \
             patch.object(flame_client, '_CACHE_META', meta_file):

            loaded = flame_client._load_cache()
            assert loaded is None


class TestGetThreatPaths:
    """Test the main get_threat_paths() function."""

    @patch("shared.flame_client._fetch_index")
    @patch("shared.flame_client._load_cache")
    def test_cache_hit_no_network(self, mock_cache, mock_fetch):
        mock_cache.return_value = SAMPLE_INDEX
        result = flame_client.get_threat_paths()

        assert len(result) == 2
        mock_fetch.assert_not_called()

    @patch("shared.flame_client._save_cache")
    @patch("shared.flame_client._fetch_index")
    @patch("shared.flame_client._load_cache")
    def test_cache_miss_triggers_fetch(self, mock_cache, mock_fetch, mock_save):
        mock_cache.return_value = None
        mock_fetch.return_value = SAMPLE_INDEX

        result = flame_client.get_threat_paths()
        assert len(result) == 2
        mock_fetch.assert_called_once()
        mock_save.assert_called_once()

    @patch("shared.flame_client._force_cache_fallback")
    @patch("shared.flame_client._fetch_index")
    @patch("shared.flame_client._load_cache")
    def test_both_fail_returns_stale_or_empty(self, mock_cache, mock_fetch, mock_fallback):
        mock_cache.return_value = None
        mock_fetch.return_value = None
        mock_fallback.return_value = []

        result = flame_client.get_threat_paths()
        assert result == []
        mock_fallback.assert_called_once()


class TestGetTpSummariesForPrompt:
    """Test prompt string generation."""

    @patch("shared.flame_client.get_threat_paths")
    def test_generates_formatted_string(self, mock_tps):
        mock_tps.return_value = SAMPLE_INDEX
        result = flame_client.get_tp_summaries_for_prompt()

        assert "FLAME Threat Path Taxonomy" in result
        assert "TP-0001" in result
        assert "TP-0002" in result
        assert "Treasury Management ATO" in result
        assert "Business Email Compromise" in result

    @patch("shared.flame_client.get_threat_paths")
    def test_empty_when_no_paths(self, mock_tps):
        mock_tps.return_value = []
        result = flame_client.get_tp_summaries_for_prompt()
        assert result == ""
