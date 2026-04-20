#!/usr/bin/env python3
"""Tests for VPN Exit IP intelligence collection."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from unittest.mock import patch, MagicMock

from vpn_ip_intel import MullvadProvider, NordVPNProvider, ProtonVPNProvider, AstrillProvider, BaseProvider, load_vpn_lookup


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


class TestNordVPNProvider:
    SAMPLE_API_RESPONSE = [
        {
            "id": 1,
            "hostname": "us1234.nordvpn.com",
            "station": "198.44.136.1",
            "status": "online",
            "locations": [
                {"country": {"code": "US", "city": {"name": "New York"}}}
            ],
            "technologies": [
                {"id": 35, "name": "Wireguard"},
                {"id": 3, "name": "OpenVPN UDP"},
            ],
        },
        {
            "id": 2,
            "hostname": "de5678.nordvpn.com",
            "station": "194.233.96.2",
            "status": "offline",
            "locations": [
                {"country": {"code": "DE", "city": {"name": "Berlin"}}}
            ],
            "technologies": [{"id": 35, "name": "Wireguard"}],
        },
    ]

    def test_parse_online_servers_only(self):
        provider = NordVPNProvider()
        with patch("vpn_ip_intel.requests") as mock_requests:
            mock_resp = MagicMock()
            mock_resp.json.return_value = self.SAMPLE_API_RESPONSE
            mock_resp.raise_for_status = MagicMock()
            mock_requests.get.return_value = mock_resp
            nodes = provider.fetch()
        assert len(nodes) == 1
        assert nodes[0]["ip"] == "198.44.136.1"
        assert nodes[0]["provider"] == "nordvpn"
        assert nodes[0]["country"] == "US"
        assert nodes[0]["hostname"] == "us1234.nordvpn.com"


class TestProtonVPNProvider:
    SAMPLE_API_RESPONSE = {
        "Code": 1000,
        "LogicalServers": [
            {
                "Name": "CH#1",
                "EntryCountry": "CH",
                "ExitCountry": "CH",
                "City": "Zurich",
                "Status": 1,
                "Servers": [
                    {"EntryIP": "185.159.157.1", "ExitIP": "185.159.157.2", "Status": 1}
                ],
                "Features": 0,
            },
            {
                "Name": "JP#5",
                "EntryCountry": "JP",
                "ExitCountry": "JP",
                "City": "Tokyo",
                "Status": 0,
                "Servers": [
                    {"EntryIP": "138.199.0.1", "ExitIP": "138.199.0.2", "Status": 0}
                ],
                "Features": 0,
            },
        ],
    }

    def test_parse_online_servers_only(self):
        provider = ProtonVPNProvider(token="test-token")
        with patch("vpn_ip_intel.requests") as mock_requests:
            mock_resp = MagicMock()
            mock_resp.json.return_value = self.SAMPLE_API_RESPONSE
            mock_resp.raise_for_status = MagicMock()
            mock_requests.get.return_value = mock_resp
            nodes = provider.fetch()
        assert len(nodes) == 1
        assert nodes[0]["ip"] == "185.159.157.2"
        assert nodes[0]["provider"] == "protonvpn"
        assert nodes[0]["country"] == "CH"


class TestAstrillProvider:
    def test_load_seed_file(self, tmp_path):
        seed = tmp_path / "seed.txt"
        seed.write_text("1.2.3.4\n5.6.7.8\n\n9.10.11.12\n")

        provider = AstrillProvider(seed_path=str(seed))
        with patch.object(provider, "_rdap_validate", return_value={"1.2.3.4"}), \
             patch.object(provider, "_shodan_org_search", return_value={"99.99.99.99"}):
            nodes = provider.fetch()

        assert len(nodes) == 4  # 3 from seed + 1 from Shodan
        confirmed = [n for n in nodes if n["confidence"] == "confirmed"]
        assert len(confirmed) == 1
        assert confirmed[0]["ip"] == "1.2.3.4"

    def test_shodan_new_ips_added(self, tmp_path):
        seed = tmp_path / "seed.txt"
        seed.write_text("1.1.1.1\n")

        provider = AstrillProvider(seed_path=str(seed))
        with patch.object(provider, "_rdap_validate", return_value=set()), \
             patch.object(provider, "_shodan_org_search", return_value={"2.2.2.2", "3.3.3.3"}):
            nodes = provider.fetch()

        ips = {n["ip"] for n in nodes}
        assert "2.2.2.2" in ips
        assert "3.3.3.3" in ips
        shodan_nodes = [n for n in nodes if n["source"] == "shodan_org"]
        assert len(shodan_nodes) == 2
        assert all(n["confidence"] == "high" for n in shodan_nodes)


class TestVPNRiskTagging:
    def test_load_vpn_lookup(self, tmp_path):
        csv_path = tmp_path / "vpn_exit_ips.csv"
        csv_path.write_text(
            "ip,provider,confidence,country,city,server_type,asn,asn_name,source,source_date,hostname\n"
            "1.2.3.4,mullvad,confirmed,se,Gothenburg,wireguard,AS39351,ESAB,mullvad_api,2026-04-19,se-got-wg-001\n"
            "5.6.7.8,astrill,medium,us,,exit,AS62240,Clouvider,spur_2024,2026-04-19,\n"
        )
        lookup = load_vpn_lookup(str(csv_path))
        assert "1.2.3.4" in lookup
        assert lookup["1.2.3.4"]["provider"] == "mullvad"
        assert "5.6.7.8" in lookup
        assert lookup["5.6.7.8"]["provider"] == "astrill"
        assert "9.9.9.9" not in lookup

    def test_risk_tag_format(self, tmp_path):
        csv_path = tmp_path / "vpn_exit_ips.csv"
        csv_path.write_text(
            "ip,provider,confidence,country,city,server_type,asn,asn_name,source,source_date,hostname\n"
            "1.2.3.4,mullvad,confirmed,se,Gothenburg,wireguard,AS39351,ESAB,mullvad_api,2026-04-19,\n"
        )
        lookup = load_vpn_lookup(str(csv_path))
        tag = f"VPN:{lookup['1.2.3.4']['provider'].title()}"
        assert tag == "VPN:Mullvad"
