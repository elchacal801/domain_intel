#!/usr/bin/env python3
"""Tests for RDAP client block CIDR extraction."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from unittest.mock import patch, MagicMock
from shared.rdap_client import RDAPClient


class TestCheckBlockCidr:
    """Test check_block_cidr extracts both name and CIDR from RDAP."""

    SAMPLE_RDAP_RESPONSE = {
        "name": "MULLVAD-US-MKC",
        "startAddress": "155.2.190.0",
        "endAddress": "155.2.191.255",
        "cidr0_cidrs": [
            {"v4prefix": "155.2.190.0", "length": 23}
        ],
        "entities": [
            {
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "THG Hosting Limited"]
                ]]
            }
        ]
    }

    def test_returns_name_and_cidr(self, tmp_path):
        client = RDAPClient(cache_dir=str(tmp_path))
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self.SAMPLE_RDAP_RESPONSE
        with patch.object(client.session, "get", return_value=mock_resp):
            name, cidr = client.check_block_cidr("155.2.191.3")
        assert name == "MULLVAD-US-MKC"
        assert cidr == "155.2.190.0/23"

    def test_falls_back_to_start_end_when_no_cidr0(self, tmp_path):
        response = {
            "name": "SOME-BLOCK",
            "startAddress": "10.0.0.0",
            "endAddress": "10.0.1.255",
            "entities": []
        }
        client = RDAPClient(cache_dir=str(tmp_path))
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = response
        with patch.object(client.session, "get", return_value=mock_resp):
            name, cidr = client.check_block_cidr("10.0.0.1")
        assert name == "SOME-BLOCK"
        assert cidr == "10.0.0.0/23"

    def test_returns_empty_on_failure(self, tmp_path):
        client = RDAPClient(cache_dir=str(tmp_path))
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch.object(client.session, "get", return_value=mock_resp):
            name, cidr = client.check_block_cidr("192.168.1.1")
        assert name == ""
        assert cidr == ""

    def test_returns_empty_cidr_when_no_address_fields(self, tmp_path):
        response = {"name": "ORPHAN-BLOCK", "entities": []}
        client = RDAPClient(cache_dir=str(tmp_path))
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = response
        with patch.object(client.session, "get", return_value=mock_resp):
            name, cidr = client.check_block_cidr("1.2.3.4")
        assert name == "ORPHAN-BLOCK"
        assert cidr == ""
