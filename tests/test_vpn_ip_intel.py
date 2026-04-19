#!/usr/bin/env python3
"""Tests for VPN Exit IP intelligence collection."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from unittest.mock import patch, MagicMock

from vpn_ip_intel import MullvadProvider, BaseProvider


class TestMullvadProvider:
    """Test Mullvad API response parsing."""

    SAMPLE_API_RESPONSE = [
        {
            "hostname": "se-got-wg-001",
            "country_code": "se",
            "country_name": "Sweden",
            "city_code": "got",
            "city_name": "Gothenburg",
            "fqdn": "se-got-wg-001.relays.mullvad.net",
            "active": True,
            "owned": True,
            "provider": "31173",
            "ipv4_addr_in": "185.213.154.68",
            "ipv6_addr_in": "2a03:1b20:5:f011::a01f",
            "network_port_speed": 10,
            "stboot": True,
            "type": "wireguard",
        },
        {
            "hostname": "us-nyc-wg-301",
            "country_code": "us",
            "country_name": "USA",
            "city_code": "nyc",
            "city_name": "New York",
            "fqdn": "us-nyc-wg-301.relays.mullvad.net",
            "active": True,
            "owned": False,
            "provider": "M247",
            "ipv4_addr_in": "146.70.174.2",
            "ipv6_addr_in": None,
            "network_port_speed": 10,
            "stboot": True,
            "type": "wireguard",
        },
        {
            "hostname": "de-ber-br-001",
            "country_code": "de",
            "country_name": "Germany",
            "city_code": "ber",
            "city_name": "Berlin",
            "fqdn": "de-ber-br-001.relays.mullvad.net",
            "active": False,
            "owned": False,
            "provider": "M247",
            "ipv4_addr_in": "10.0.0.1",
            "ipv6_addr_in": None,
            "network_port_speed": 10,
            "stboot": True,
            "type": "bridge",
        },
    ]

    def test_parse_active_servers_only(self):
        provider = MullvadProvider()
        with patch("vpn_ip_intel.requests") as mock_requests:
            mock_resp = MagicMock()
            mock_resp.json.return_value = self.SAMPLE_API_RESPONSE
            mock_resp.status_code = 200
            mock_resp.raise_for_status = MagicMock()
            mock_requests.get.return_value = mock_resp
            nodes = provider.fetch()
        assert len(nodes) == 2
        assert nodes[0]["ip"] == "185.213.154.68"
        assert nodes[0]["provider"] == "mullvad"
        assert nodes[0]["confidence"] == "confirmed"
        assert nodes[0]["country"] == "se"
        assert nodes[0]["server_type"] == "wireguard"
        assert nodes[0]["hostname"] == "se-got-wg-001"

    def test_all_nodes_have_required_fields(self):
        provider = MullvadProvider()
        with patch("vpn_ip_intel.requests") as mock_requests:
            mock_resp = MagicMock()
            mock_resp.json.return_value = self.SAMPLE_API_RESPONSE
            mock_resp.raise_for_status = MagicMock()
            mock_requests.get.return_value = mock_resp
            nodes = provider.fetch()
        required = {"ip", "provider", "confidence", "country", "city",
                    "server_type", "source", "source_date", "hostname"}
        for node in nodes:
            assert required.issubset(node.keys()), f"Missing keys: {required - node.keys()}"

    def test_skips_entries_without_ipv4(self):
        data = [{"hostname": "test", "active": True, "ipv4_addr_in": None,
                 "country_code": "se", "city_name": "Stockholm", "type": "wireguard"}]
        provider = MullvadProvider()
        with patch("vpn_ip_intel.requests") as mock_requests:
            mock_resp = MagicMock()
            mock_resp.json.return_value = data
            mock_resp.raise_for_status = MagicMock()
            mock_requests.get.return_value = mock_resp
            nodes = provider.fetch()
        assert len(nodes) == 0
