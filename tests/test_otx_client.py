#!/usr/bin/env python3
"""Tests for shared.otx_client module."""

import os
import sys

import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from shared.otx_client import query_otx_passive_dns, resolve_target


class TestResolveTarget:
    """Test target resolution (IP passthrough vs DNS lookup)."""

    def test_valid_ip_returned_directly(self):
        result = resolve_target("1.2.3.4")
        assert result == "1.2.3.4"

    @patch("shared.otx_client.socket.gethostbyname", return_value="93.184.216.34")
    def test_domain_resolves_to_ip(self, mock_dns):
        result = resolve_target("example.com")
        assert result == "93.184.216.34"
        mock_dns.assert_called_once_with("example.com")

    @patch("shared.otx_client.socket.gethostbyname")
    def test_unresolvable_domain_returns_none(self, mock_dns):
        import socket
        mock_dns.side_effect = socket.gaierror("DNS failure")
        result = resolve_target("nonexistent.invalid")
        assert result is None


class TestQueryOtxPassiveDns:
    """Test OTX passive DNS querying."""

    @patch("shared.otx_client.OTX_API_KEY", "test-key")
    @patch("shared.otx_client.requests.get")
    def test_successful_query_returns_hostnames(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "passive_dns": [
                {"hostname": "example.com", "address": "1.2.3.4"},
                {"hostname": "test.com", "address": "1.2.3.4"},
                {"hostname": None, "address": "1.2.3.4"},  # should be filtered
            ]
        }
        mock_get.return_value = mock_resp

        result = query_otx_passive_dns("1.2.3.4")
        assert result == ["example.com", "test.com"]

    @patch("shared.otx_client.OTX_API_KEY", "test-key")
    @patch("shared.otx_client.requests.get")
    def test_non_200_returns_empty(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_get.return_value = mock_resp

        result = query_otx_passive_dns("1.2.3.4")
        assert result == []

    @patch("shared.otx_client.OTX_API_KEY", "test-key")
    @patch("shared.otx_client.requests.get")
    def test_timeout_returns_empty(self, mock_get):
        import requests
        mock_get.side_effect = requests.Timeout("connection timed out")

        result = query_otx_passive_dns("1.2.3.4")
        assert result == []

    @patch("shared.otx_client.OTX_API_KEY", None)
    def test_missing_api_key_returns_empty(self):
        result = query_otx_passive_dns("1.2.3.4")
        assert result == []
