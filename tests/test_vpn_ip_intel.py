#!/usr/bin/env python3
"""Tests for VPN Exit IP intelligence collection."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from unittest.mock import patch, MagicMock

from vpn_ip_intel import (
    MullvadProvider, NordVPNProvider, ProtonVPNProvider, AstrillProvider,
    UrbanVPNProvider,
    VPNGateProvider, IPVanishProvider, FastVPNProvider, TunnelBearProvider,
    AirVPNProvider, VyprVPNProvider, ExpressVPNProvider, HotspotShieldProvider,
    HMAProvider, HolaVPNProvider, PrivadoVPNProvider, FlowVPNProvider, NjallaVPNProvider,
    OvpnConfigProvider,
    BaseProvider, load_vpn_lookup, normalize_node, compute_prefix_inferred_rows,
    compute_rdap_egress_rows,
    load_scores, join_scores, FIELDS, SCORE_FIELDS,
    SHARED_HOSTING_ASNS, _COUNTRY_ALIASES, _SERVER_TYPE_ALIASES, TODAY,
    IP_ROLES, PROVIDERS,
    load_existing_csv, merge_with_existing,
)


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
        with patch("vpn_ip_intel.requests") as mock_requests, \
             patch.object(provider, "load_exit_seeds", return_value=[]):
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
        with patch("vpn_ip_intel.requests") as mock_requests, \
             patch.object(provider, "load_exit_seeds", return_value=[]):
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
        with patch("vpn_ip_intel.requests") as mock_requests, \
             patch.object(provider, "load_exit_seeds", return_value=[]):
            mock_resp = MagicMock()
            mock_resp.json.return_value = data
            mock_resp.raise_for_status = MagicMock()
            mock_requests.get.return_value = mock_resp
            nodes = provider.fetch()
        assert len(nodes) == 0

    def test_load_exit_seeds(self, tmp_path):
        """MullvadProvider loads exit IPs from seed CSV when present."""
        seed_csv = tmp_path / "mullvad_exit_ips.csv"
        seed_csv.write_text(
            "relay_hostname,ingress_ip,exit_ip,probe_date\n"
            "us-mkc-wg-001,155.2.191.3,155.2.190.72,2026-05-03\n"
            "se-got-wg-001,185.213.154.68,185.213.154.100,2026-05-03\n"
        )

        provider = MullvadProvider()
        provider.SEED_PATH = str(seed_csv)
        egress_nodes = provider.load_exit_seeds()

        assert len(egress_nodes) == 2
        assert egress_nodes[0]["ip"] == "155.2.190.72"
        assert egress_nodes[0]["ip_role"] == "egress"
        assert egress_nodes[0]["confidence"] == "confirmed"
        assert egress_nodes[0]["source"] == "socks5_probe"
        assert egress_nodes[0]["hostname"] == "us-mkc-wg-001"

    def test_load_exit_seeds_missing_file(self, tmp_path):
        """Returns empty list when seed file doesn't exist."""
        provider = MullvadProvider()
        provider.SEED_PATH = str(tmp_path / "nonexistent.csv")
        egress_nodes = provider.load_exit_seeds()
        assert egress_nodes == []


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
    def test_parse_cache_binary(self, tmp_path):
        """Test parsing IPs and hostnames from a mock protobuf cache."""
        # Build a minimal binary with the patterns the parser expects
        cache = tmp_path / "Servers.test.bin"
        content = (
            b"\x00\x00185.159.157.2\x00\x00\x22\x00node-ch-01.protonvpn.net"
            b"\x00\x00138.199.0.1\x00\x00\x22\x00node-jp-05.protonvpn.net"
        )
        cache.write_bytes(content)

        provider = ProtonVPNProvider(cache_path=str(cache))
        nodes = provider.fetch()

        assert len(nodes) == 2
        assert nodes[0]["ip"] == "185.159.157.2"
        assert nodes[0]["provider"] == "protonvpn"
        assert nodes[0]["country"] == "CH"
        assert nodes[0]["hostname"] == "node-ch-01.protonvpn.net"
        assert nodes[1]["ip"] == "138.199.0.1"
        assert nodes[1]["country"] == "JP"


class TestAstrillProvider:
    def test_load_seed_file(self, tmp_path):
        seed = tmp_path / "seed.txt"
        seed.write_text("1.2.3.4\n5.6.7.8\n\n9.10.11.12\n")

        provider = AstrillProvider(seed_path=str(seed))
        with patch.object(provider, "_rdap_validate", return_value={"1.2.3.4"}), \
             patch("vpn_ip_intel.BaseProvider.shodan_org_search", return_value={"99.99.99.99"}):
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
             patch("vpn_ip_intel.BaseProvider.shodan_org_search", return_value={"2.2.2.2", "3.3.3.3"}):
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

    def test_load_vpn_lookup_skips_empty_ip(self, tmp_path):
        csv_path = tmp_path / "vpn_relay_ips.csv"
        csv_path.write_text(
            "ip,provider,confidence,country,city,server_type,asn,asn_name,source,source_date,hostname,collection_method,threat_relevance,ip_role,prefix\n"
            "1.2.3.4,mullvad,confirmed,SE,,wireguard,,,mullvad_api,2026-04-19,,,ingress,\n"
            ",mullvad,medium,SE,,wireguard,AS1234,Test,prefix_inferred_from_5_ips,2026-04-19,,,prefix-inferred,1.2.3.0/24\n"
        )
        lookup = load_vpn_lookup(str(csv_path))
        assert "1.2.3.4" in lookup
        assert "" not in lookup
        assert len(lookup) == 1

    def test_load_vpn_lookup_default_path(self):
        import inspect
        sig = inspect.signature(load_vpn_lookup)
        assert sig.parameters["csv_path"].default == "data/vpn_relay_ips.csv"


# === New tests: normalize_node ===

class TestNormalizeNode:
    @pytest.mark.parametrize("input_cc,expected", [
        ("se", "SE"),
        ("US", "US"),
        ("", ""),
        ("uk", "GB"),
        ("UK", "GB"),
        ("Gb", "GB"),
    ])
    def test_country_normalization(self, input_cc, expected):
        node = {"country": input_cc, "server_type": "wireguard", "hostname": "",
                "confidence": "confirmed"}
        normalize_node(node)
        assert node["country"] == expected

    @pytest.mark.parametrize("input_st,expected", [
        ("wg", "wireguard"),
        ("wireguard", "wireguard"),
        ("openvpn_udp", "openvpn"),
        ("openvpn_tcp", "openvpn"),
        ("exit", "exit"),
        ("bridge", "bridge"),
        ("WireGuard", "wireguard"),
    ])
    def test_server_type_normalization(self, input_st, expected):
        node = {"country": "", "server_type": input_st, "hostname": "",
                "confidence": "confirmed"}
        normalize_node(node)
        assert node["server_type"] == expected

    def test_hostname_lowercase(self):
        node = {"country": "", "server_type": "", "hostname": "US-NYC-WG-301.MULLVAD.NET",
                "confidence": "confirmed"}
        normalize_node(node)
        assert node["hostname"] == "us-nyc-wg-301.mullvad.net"

    @pytest.mark.parametrize("input_conf,expected", [
        ("confirmed", "confirmed"),
        ("high", "high"),
        ("medium", "medium"),
        ("low", "low"),
        ("bogus", "low"),
        ("CONFIRMED", "confirmed"),
        ("", "low"),
    ])
    def test_confidence_clamping(self, input_conf, expected):
        node = {"country": "", "server_type": "", "hostname": "",
                "confidence": input_conf}
        normalize_node(node)
        assert node["confidence"] == expected

    def test_idempotent(self):
        node = {"country": "uk", "server_type": "wg", "hostname": "TEST.COM",
                "confidence": "high", "ip_role": "ingress", "prefix": ""}
        normalize_node(node)
        first = dict(node)
        normalize_node(node)
        assert node == first

    def test_defaults_ip_role_and_prefix(self):
        node = {"country": "", "server_type": "", "hostname": "", "confidence": "confirmed"}
        normalize_node(node)
        assert node["ip_role"] == "unknown"
        assert node["prefix"] == ""

    def test_preserves_existing_ip_role(self):
        node = {"country": "", "server_type": "", "hostname": "", "confidence": "confirmed",
                "ip_role": "egress", "prefix": ""}
        normalize_node(node)
        assert node["ip_role"] == "egress"


# === New tests: Astrill seed date ===

class TestSeedDate:
    def test_seed_date_parses_year(self, tmp_path):
        seed = tmp_path / "spur_astrill_2024.txt"
        seed.write_text("1.2.3.4\n")
        provider = AstrillProvider(seed_path=str(seed))
        assert provider._seed_date() == "2024-01-01"

    def test_seed_date_no_year(self, tmp_path):
        seed = tmp_path / "astrill.txt"
        seed.write_text("1.2.3.4\n")
        provider = AstrillProvider(seed_path=str(seed))
        assert provider._seed_date() == TODAY

    def test_stale_seed_warning(self, tmp_path, caplog):
        import logging
        seed = tmp_path / "spur_astrill_2024.txt"
        seed.write_text("1.2.3.4\n")
        provider = AstrillProvider(seed_path=str(seed))
        with patch.object(provider, "_rdap_validate", return_value=set()), \
             patch("vpn_ip_intel.BaseProvider.shodan_org_search", return_value=set()), \
             caplog.at_level(logging.WARNING):
            provider.fetch()
        assert any("days old" in r.message for r in caplog.records)


# === New tests: Astrill egress tagging ===

class TestAstrillEgress:
    def test_seed_ips_tagged_egress(self, tmp_path):
        seed = tmp_path / "spur_astrill_2024.txt"
        seed.write_text("1.2.3.4\n5.6.7.8\n")
        provider = AstrillProvider(seed_path=str(seed))
        with patch.object(provider, "_rdap_validate", return_value=set()), \
             patch("vpn_ip_intel.BaseProvider.shodan_org_search", return_value=set()):
            nodes = provider.fetch()
        assert all(n["ip_role"] == "egress" for n in nodes)

    def test_shodan_ips_tagged_egress(self, tmp_path):
        seed = tmp_path / "spur_astrill_2024.txt"
        seed.write_text("1.2.3.4\n")
        provider = AstrillProvider(seed_path=str(seed))
        with patch.object(provider, "_rdap_validate", return_value=set()), \
             patch("vpn_ip_intel.BaseProvider.shodan_org_search", return_value={"9.9.9.9"}):
            nodes = provider.fetch()
        shodan_nodes = [n for n in nodes if n["source"] == "shodan_org"]
        assert len(shodan_nodes) == 1
        assert shodan_nodes[0]["ip_role"] == "egress"

    def test_seed_date_applied_to_seed_rows(self, tmp_path):
        seed = tmp_path / "spur_astrill_2024.txt"
        seed.write_text("1.2.3.4\n")
        provider = AstrillProvider(seed_path=str(seed))
        with patch.object(provider, "_rdap_validate", return_value=set()), \
             patch("vpn_ip_intel.BaseProvider.shodan_org_search", return_value={"9.9.9.9"}):
            nodes = provider.fetch()
        seed_node = [n for n in nodes if n["ip"] == "1.2.3.4"][0]
        shodan_node = [n for n in nodes if n["ip"] == "9.9.9.9"][0]
        assert seed_node["source_date"] == "2024-01-01"
        assert shodan_node["source_date"] == TODAY


# === New tests: ProtonVPN cache fallback ===

class TestProtonCacheFallback:
    def test_find_cache_repo_local(self, tmp_path, monkeypatch):
        # Create a mock repo structure
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        seed_dir = tmp_path / "data" / "vpn_seeds" / "protonvpn"
        seed_dir.mkdir(parents=True)
        cache = seed_dir / "Servers.abc123.bin"
        cache.write_bytes(b"\x00" * 10)

        import vpn_ip_intel
        monkeypatch.setattr(vpn_ip_intel, "__file__", str(scripts_dir / "vpn_ip_intel.py"))
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
        provider = ProtonVPNProvider()
        result = provider._find_cache()
        assert "Servers.abc123.bin" in result

    def test_find_cache_prefers_current(self, tmp_path, monkeypatch):
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        seed_dir = tmp_path / "data" / "vpn_seeds" / "protonvpn"
        seed_dir.mkdir(parents=True)
        (seed_dir / "Servers.abc123.bin").write_bytes(b"\x00")
        (seed_dir / "Servers.current.bin").write_bytes(b"\x00")

        import vpn_ip_intel
        original = vpn_ip_intel.__file__
        monkeypatch.setattr(vpn_ip_intel, "__file__", str(scripts_dir / "vpn_ip_intel.py"))
        provider = ProtonVPNProvider()
        result = provider._find_cache()
        monkeypatch.setattr(vpn_ip_intel, "__file__", original)
        assert "Servers.current.bin" in result

    def test_missing_cache_warning(self, tmp_path, caplog, monkeypatch):
        import logging
        import vpn_ip_intel
        # Point to empty dir so no cache found
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        original = vpn_ip_intel.__file__
        monkeypatch.setattr(vpn_ip_intel, "__file__", str(scripts_dir / "vpn_ip_intel.py"))
        monkeypatch.delenv("LOCALAPPDATA", raising=False)

        provider = ProtonVPNProvider()
        with caplog.at_level(logging.WARNING):
            nodes = provider.fetch()
        monkeypatch.setattr(vpn_ip_intel, "__file__", original)
        assert len(nodes) == 0
        assert any("no local client cache found" in r.message for r in caplog.records)


# === New tests: Prefix inference ===

class TestPrefixInferred:
    def _make_nodes(self, ips, provider="mullvad", asn="AS1234"):
        return [
            {"ip": ip, "provider": provider, "confidence": "confirmed",
             "country": "SE", "city": "", "server_type": "wireguard",
             "asn": asn, "asn_name": "TestASN", "source": "test",
             "source_date": TODAY, "hostname": "", "collection_method": "test",
             "threat_relevance": "test", "ip_role": "ingress", "prefix": ""}
            for ip in ips
        ]

    def test_prefix_widening_threshold(self):
        nodes = self._make_nodes(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])
        result = compute_prefix_inferred_rows(nodes)
        assert len(result) == 1
        assert result[0]["ip_role"] == "prefix-inferred"
        assert result[0]["prefix"] == "10.0.0.0/24"
        assert result[0]["ip"] == ""
        assert result[0]["confidence"] == "medium"

    def test_prefix_below_threshold(self):
        nodes = self._make_nodes(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        result = compute_prefix_inferred_rows(nodes)
        assert len(result) == 0

    def test_shared_asn_skip(self):
        nodes = self._make_nodes(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
            asn="AS16509"  # AWS
        )
        result = compute_prefix_inferred_rows(nodes)
        assert len(result) == 0

    def test_empty_asn_skip(self):
        nodes = self._make_nodes(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
            asn=""
        )
        result = compute_prefix_inferred_rows(nodes)
        assert len(result) == 0

    def test_mixed_providers_grouped_separately(self):
        nodes_a = self._make_nodes(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
            provider="mullvad"
        )
        nodes_b = self._make_nodes(
            ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"],
            provider="nordvpn"
        )
        result = compute_prefix_inferred_rows(nodes_a + nodes_b)
        # Both providers have >=4 in same /24 but different groups
        assert len(result) == 2
        providers = {r["provider"] for r in result}
        assert providers == {"mullvad", "nordvpn"}


# === New test: Explicit 104.36.50.32 coverage ===

class TestExplicitIP:
    def test_104_36_50_32_coverage(self, tmp_path):
        """The IP that originally prompted this feature gets prefix-inferred coverage."""
        # Simulate 4 Astrill IPs in the same /24 as 104.36.50.32
        nodes = [
            {"ip": f"104.36.50.{i}", "provider": "astrill", "confidence": "medium",
             "country": "", "city": "", "server_type": "exit",
             "asn": "AS62240", "asn_name": "Clouvider", "source": "spur_2024",
             "source_date": "2024-01-01", "hostname": "", "collection_method": "test",
             "threat_relevance": "test", "ip_role": "egress", "prefix": ""}
            for i in [10, 20, 30, 40]
        ]
        prefix_rows = compute_prefix_inferred_rows(nodes)
        assert len(prefix_rows) == 1
        assert prefix_rows[0]["prefix"] == "104.36.50.0/24"
        # 104.36.50.32 falls within this prefix
        import ipaddress
        net = ipaddress.ip_network(prefix_rows[0]["prefix"])
        assert ipaddress.ip_address("104.36.50.32") in net


# === UrbanVPN Provider Tests ===

class TestUrbanVPN:
    """Test Urban VPN provider."""

    @patch("vpn_ip_intel.BaseProvider.shodan_org_search")
    def test_fetch_returns_correct_nodes(self, mock_shodan):
        mock_shodan.return_value = {"1.2.3.4", "5.6.7.8"}
        prov = UrbanVPNProvider()
        nodes = prov.fetch()
        assert len(nodes) == 2
        ips = {n["ip"] for n in nodes}
        assert ips == {"1.2.3.4", "5.6.7.8"}
        for n in nodes:
            assert n["provider"] == "urbanvpn"
            assert n["confidence"] == "high"
            assert n["ip_role"] == "unknown"
            assert n["source"] == "shodan_org"
            assert n["source_date"] == TODAY
            assert n["server_type"] == "exit"
        mock_shodan.assert_called_once_with("Urban VPN")

    @patch("vpn_ip_intel.BaseProvider.shodan_org_search")
    def test_fetch_empty_when_shodan_unavailable(self, mock_shodan):
        mock_shodan.return_value = set()
        prov = UrbanVPNProvider()
        nodes = prov.fetch()
        assert nodes == []

    def test_provider_attributes(self):
        prov = UrbanVPNProvider()
        assert prov.name == "urbanvpn"
        assert prov.display_name == "Urban VPN"
        assert prov.collection_method == "Shodan org search"
        assert "DPRK" in prov.threat_relevance


# === Score Join Tests ===

class TestScoreJoin:
    """Test provider score join logic."""

    def _write_scores_csv(self, tmp_path):
        """Write a minimal scores CSV for testing."""
        path = tmp_path / "vpn_provider_scores.csv"
        path.write_text(
            "provider,confidence,score_prehire,tier_prehire,score_posthire,tier_posthire,indicator_id\n"
            "astrill,confirmed,25,anchor,30,anchor,VPN-001\n"
            "astrill,medium,20,strong,20,strong,VPN-002\n"
            "urbanvpn,high,10,contextual,15,strong,VPN-019\n"
        )
        return str(path)

    def test_load_scores(self, tmp_path):
        path = self._write_scores_csv(tmp_path)
        scores = load_scores(path)
        assert ("astrill", "confirmed") in scores
        assert scores[("astrill", "confirmed")]["score_prehire"] == "25"
        assert scores[("astrill", "confirmed")]["indicator_id"] == "VPN-001"

    def test_join_scores_matched(self, tmp_path):
        path = self._write_scores_csv(tmp_path)
        nodes = [
            {"ip": "1.2.3.4", "provider": "astrill", "confidence": "confirmed"},
        ]
        join_scores(nodes, path)
        assert nodes[0]["score_prehire"] == "25"
        assert nodes[0]["tier_prehire"] == "anchor"
        assert nodes[0]["score_posthire"] == "30"
        assert nodes[0]["tier_posthire"] == "anchor"
        assert nodes[0]["indicator_id"] == "VPN-001"

    def test_join_scores_unmatched_defaults(self, tmp_path):
        path = self._write_scores_csv(tmp_path)
        nodes = [
            {"ip": "9.9.9.9", "provider": "unknown_provider", "confidence": "low"},
        ]
        join_scores(nodes, path)
        assert nodes[0]["score_prehire"] == "5"
        assert nodes[0]["tier_prehire"] == "contextual"
        assert nodes[0]["score_posthire"] == "5"
        assert nodes[0]["tier_posthire"] == "contextual"
        assert nodes[0]["indicator_id"] == ""

    def test_fields_include_score_columns(self):
        for col in ["score_prehire", "tier_prehire", "score_posthire", "tier_posthire", "indicator_id"]:
            assert col in FIELDS, f"{col} missing from FIELDS"

    def test_prefix_inferred_inherits_scores(self, tmp_path):
        """Prefix-inferred rows should carry scores from their template node."""
        path = self._write_scores_csv(tmp_path)
        nodes = [
            {"ip": f"10.0.0.{i}", "provider": "astrill", "confidence": "confirmed",
             "country": "", "city": "", "server_type": "exit",
             "asn": "AS12345", "asn_name": "Test", "source": "test",
             "source_date": TODAY, "hostname": "", "collection_method": "test",
             "threat_relevance": "test", "ip_role": "egress", "prefix": ""}
            for i in range(1, 5)
        ]
        # Join scores first (like run() does)
        join_scores(nodes, path)
        assert nodes[0]["score_prehire"] == "25"

        # Then compute prefix rows
        prefix_rows = compute_prefix_inferred_rows(nodes)
        assert len(prefix_rows) == 1
        assert prefix_rows[0]["score_prehire"] == "25"
        assert prefix_rows[0]["tier_prehire"] == "anchor"
        assert prefix_rows[0]["indicator_id"] == "VPN-001"

    def test_load_scores_missing_file(self, tmp_path):
        scores = load_scores(str(tmp_path / "nonexistent.csv"))
        assert scores == {}


class TestEgressInferred:
    """Test egress-inferred role and dedup changes."""

    def test_egress_inferred_in_ip_roles(self):
        assert "egress-inferred" in IP_ROLES

    def test_dedup_keeps_both_ingress_and_egress(self):
        """Same IP with different roles should both survive dedup."""
        nodes = [
            {"ip": "1.2.3.4", "provider": "mullvad", "ip_role": "ingress"},
            {"ip": "1.2.3.4", "provider": "mullvad", "ip_role": "egress"},
        ]
        seen = set()
        deduped = []
        for n in nodes:
            key = (n["ip"], n["provider"], n["ip_role"])
            if key not in seen:
                seen.add(key)
                deduped.append(n)
        assert len(deduped) == 2

    def test_dedup_removes_true_duplicates(self):
        """Same IP, provider, AND role should dedup to one."""
        nodes = [
            {"ip": "1.2.3.4", "provider": "mullvad", "ip_role": "ingress"},
            {"ip": "1.2.3.4", "provider": "mullvad", "ip_role": "ingress"},
        ]
        seen = set()
        deduped = []
        for n in nodes:
            key = (n["ip"], n["provider"], n["ip_role"])
            if key not in seen:
                seen.add(key)
                deduped.append(n)
        assert len(deduped) == 1


class TestRDAPEgressExpansion:
    """Test RDAP-based egress prefix expansion."""

    def _make_ingress_nodes(self, ips, provider="mullvad", asn="AS13213"):
        return [
            {"ip": ip, "provider": provider, "confidence": "confirmed",
             "country": "US", "city": "Kansas City, MO", "server_type": "wireguard",
             "asn": asn, "asn_name": "UK2NET-AS, GB", "source": "mullvad_api",
             "source_date": TODAY, "hostname": f"us-mkc-wg-{i:03d}",
             "collection_method": "Public API",
             "threat_relevance": "Verified no-logs", "ip_role": "ingress", "prefix": "",
             "score_prehire": "8", "tier_prehire": "contextual",
             "score_posthire": "8", "tier_posthire": "contextual",
             "indicator_id": "VPN-007"}
            for i, ip in enumerate(ips, 1)
        ]

    @patch("vpn_ip_intel.RDAPClient")
    def test_expands_adjacent_prefixes(self, MockRDAP):
        """If RDAP says 155.2.190.0/23 is one block, and we have IPs in 155.2.191.0/24,
        then 155.2.190.0/24 should get an egress-inferred row."""
        mock_client = MockRDAP.return_value
        mock_client.check_block_cidr.return_value = ("MULLVAD-US-MKC", "155.2.190.0/23")

        nodes = self._make_ingress_nodes([
            "155.2.191.3", "155.2.191.53", "155.2.191.103", "155.2.191.153"
        ])
        result = compute_rdap_egress_rows(nodes, rdap=mock_client)

        assert len(result) == 1
        assert result[0]["ip"] == ""
        assert result[0]["prefix"] == "155.2.190.0/24"
        assert result[0]["ip_role"] == "egress-inferred"
        assert result[0]["confidence"] == "medium"
        assert result[0]["source"] == "rdap_prefix_expansion"
        assert result[0]["provider"] == "mullvad"

    @patch("vpn_ip_intel.RDAPClient")
    def test_skips_shared_hosting_asns(self, MockRDAP):
        mock_client = MockRDAP.return_value
        nodes = self._make_ingress_nodes(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
            asn="AS16509"  # AWS
        )
        result = compute_rdap_egress_rows(nodes, rdap=mock_client)
        assert len(result) == 0
        mock_client.check_block_cidr.assert_not_called()

    @patch("vpn_ip_intel.RDAPClient")
    def test_skips_prefix_already_covered(self, MockRDAP):
        """If we already have IPs in a /24, don't emit an egress-inferred row for it."""
        mock_client = MockRDAP.return_value
        mock_client.check_block_cidr.return_value = ("BLOCK", "10.0.0.0/23")

        nodes = self._make_ingress_nodes(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])
        nodes.extend(self._make_ingress_nodes(["10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4"]))
        result = compute_rdap_egress_rows(nodes, rdap=mock_client)
        assert len(result) == 0

    @patch("vpn_ip_intel.RDAPClient")
    def test_no_expansion_when_rdap_fails(self, MockRDAP):
        mock_client = MockRDAP.return_value
        mock_client.check_block_cidr.return_value = ("", "")

        nodes = self._make_ingress_nodes(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])
        result = compute_rdap_egress_rows(nodes, rdap=mock_client)
        assert len(result) == 0

    @patch("vpn_ip_intel.RDAPClient")
    def test_only_processes_ingress_nodes(self, MockRDAP):
        """Nodes with ip_role != ingress should not trigger expansion."""
        mock_client = MockRDAP.return_value
        nodes = self._make_ingress_nodes(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])
        for n in nodes:
            n["ip_role"] = "egress"
        result = compute_rdap_egress_rows(nodes, rdap=mock_client)
        assert len(result) == 0
        mock_client.check_block_cidr.assert_not_called()


class TestProviderRegistry:
    """Verify all providers are registered and have required attributes."""

    def test_provider_count(self):
        assert len(PROVIDERS) == 20  # HolaVPN, HMA, IPVanish disabled

    def test_all_providers_have_required_attrs(self):
        for p in PROVIDERS:
            assert p.name, f"{p.__class__.__name__} missing name"
            assert p.display_name, f"{p.__class__.__name__} missing display_name"
            assert p.collection_method, f"{p.__class__.__name__} missing collection_method"
            assert p.threat_relevance, f"{p.__class__.__name__} missing threat_relevance"

    def test_unique_provider_names(self):
        names = [p.name for p in PROVIDERS]
        assert len(names) == len(set(names)), f"Duplicate names: {[n for n in names if names.count(n) > 1]}"


class TestVPNGateProvider:
    """Test VPN Gate CSV API parsing."""

    SAMPLE_CSV = (
        "*vpn_servers\n"
        "HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
        "vpn123,1.2.3.4,1000,10,50000,Japan,JP,5,100,1000,5000,2weeks,op1,msg1,base64data\n"
        "vpn456,5.6.7.8,800,20,30000,United States,US,3,200,500,3000,2weeks,op2,msg2,base64data\n"
        "*vpn_servers\n"
    )

    def test_parse_csv_response(self):
        provider = VPNGateProvider()
        mock_resp = MagicMock()
        mock_resp.text = self.SAMPLE_CSV
        mock_resp.raise_for_status = MagicMock()
        with patch("vpn_ip_intel.requests.get", return_value=mock_resp):
            nodes = provider.fetch()
        assert len(nodes) == 2
        assert nodes[0]["ip"] == "1.2.3.4"
        assert nodes[0]["country"] == "JP"
        assert nodes[0]["provider"] == "vpngate"
        assert nodes[1]["ip"] == "5.6.7.8"
        assert nodes[1]["country"] == "US"

    def test_skips_duplicate_ips(self):
        csv = (
            "*vpn_servers\n"
            "HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
            "vpn1,1.2.3.4,1000,10,50000,Japan,JP,5,100,1000,5000,2weeks,op,msg,b64\n"
            "vpn2,1.2.3.4,800,20,30000,Japan,JP,3,200,500,3000,2weeks,op,msg,b64\n"
            "*vpn_servers\n"
        )
        provider = VPNGateProvider()
        mock_resp = MagicMock()
        mock_resp.text = csv
        mock_resp.raise_for_status = MagicMock()
        with patch("vpn_ip_intel.requests.get", return_value=mock_resp):
            nodes = provider.fetch()
        assert len(nodes) == 1


class TestAirVPNProvider:
    """Test AirVPN JSON API parsing."""

    SAMPLE_RESPONSE = {
        "servers": [
            {
                "public_name": "Achernar",
                "country_code": "ch",
                "location": "Zurich",
                "ip_v4_in1": "185.156.175.170",
                "ip_v4_in2": "185.156.175.172",
                "ip_v4_in3": "",
                "ip_v4_in4": "",
                "health": "ok",
            },
            {
                "public_name": "Adhara",
                "country_code": "de",
                "location": "Frankfurt",
                "ip_v4_in1": "185.104.184.42",
                "ip_v4_in2": "",
                "ip_v4_in3": "",
                "ip_v4_in4": "",
                "health": "ok",
            },
        ]
    }

    def test_parse_json_response(self):
        provider = AirVPNProvider()
        mock_resp = MagicMock()
        mock_resp.json.return_value = self.SAMPLE_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        with patch("vpn_ip_intel.requests.get", return_value=mock_resp):
            nodes = provider.fetch()
        assert len(nodes) == 3  # 2 from Achernar + 1 from Adhara
        assert nodes[0]["ip"] == "185.156.175.170"
        assert nodes[0]["country"] == "CH"
        assert nodes[0]["hostname"] == "Achernar"


class TestOvpnConfigProvider:
    """Test OpenVPN config ZIP parsing base class."""

    def test_parse_country_ipvanish(self):
        p = IPVanishProvider()
        assert p._parse_country("ipvanish-US-New-York-nyc-a01.ovpn") == "US"

    def test_parse_country_tunnelbear(self):
        p = TunnelBearProvider()
        assert p._parse_country("CACougar.ovpn") == "CA"
        assert p._parse_country("USGrizzly.ovpn") == "US"
        assert p._parse_country("GBMonarch.ovpn") == "GB"

    def test_parse_country_fastvpn(self):
        p = FastVPNProvider()
        assert p._parse_country("NCVPN-AD-Andorra la Vella-TCP.ovpn") == "AD"
        assert p._parse_country("NCVPN-US-Miami-UDP.ovpn") == "US"

    def test_parse_country_privadovpn(self):
        p = PrivadoVPNProvider()
        assert p._parse_country("lis-010.udp.ovpn") == "PT"
        assert p._parse_country("yyz-004.tcp.ovpn") == "CA"
        assert p._parse_country("mia-007.udp.ovpn") == "US"

    def test_make_node_has_required_fields(self):
        p = IPVanishProvider()
        node = p._make_node("1.2.3.4", "US", "test.host.com")
        required = {"ip", "provider", "confidence", "country", "city",
                    "server_type", "source", "source_date", "hostname",
                    "ip_role", "prefix"}
        assert required.issubset(node.keys())
        assert node["ip"] == "1.2.3.4"
        assert node["provider"] == "ipvanish"
        assert node["country"] == "US"

    def test_fetch_parses_zip_with_direct_ips(self):
        """Test full fetch() flow with mock ZIP containing direct IPs."""
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("ipvanish-US-test.ovpn",
                         "client\nremote 1.2.3.4 443\nproto tcp\n")
            zf.writestr("ipvanish-DE-test.ovpn",
                         "client\nremote 5.6.7.8 1194\nproto udp\n")
        zip_bytes = buf.getvalue()

        p = IPVanishProvider()
        mock_resp = MagicMock()
        mock_resp.content = zip_bytes
        mock_resp.raise_for_status = MagicMock()
        with patch("vpn_ip_intel.requests.get", return_value=mock_resp):
            nodes = p.fetch()
        assert len(nodes) == 2
        ips = {n["ip"] for n in nodes}
        assert ips == {"1.2.3.4", "5.6.7.8"}
        countries = {n["country"] for n in nodes}
        assert "US" in countries

    def test_fetch_resolves_hostnames(self):
        """Test fetch() resolves hostnames via socket."""
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("ipvanish-US-test.ovpn",
                         "client\nremote test.example.com 443\nproto tcp\n")
        zip_bytes = buf.getvalue()

        p = IPVanishProvider()
        mock_resp = MagicMock()
        mock_resp.content = zip_bytes
        mock_resp.raise_for_status = MagicMock()

        fake_addrinfo = [(2, 1, 6, '', ('93.184.216.34', 0))]
        with patch("vpn_ip_intel.requests.get", return_value=mock_resp), \
             patch("socket.getaddrinfo", return_value=fake_addrinfo):
            nodes = p.fetch()
        assert len(nodes) == 1
        assert nodes[0]["ip"] == "93.184.216.34"
        assert nodes[0]["hostname"] == "test.example.com"

    def test_rejects_oversized_zip(self):
        """Test that excessively large responses are rejected."""
        p = IPVanishProvider()
        mock_resp = MagicMock()
        mock_resp.content = b"x" * (51 * 1024 * 1024)
        mock_resp.raise_for_status = MagicMock()
        with patch("vpn_ip_intel.requests.get", return_value=mock_resp):
            nodes = p.fetch()
        assert nodes == []


class TestExpressVPNProvider:
    """Test ExpressVPN seed + Shodan provider."""

    def test_provider_attributes(self):
        p = ExpressVPNProvider()
        assert p.name == "expressvpn"
        assert "DPRK" in p.threat_relevance

    def test_fetch_with_gluetun_data(self):
        gluetun_resp = {
            "expressvpn": {
                "version": 1,
                "timestamp": 1700000000,
                "servers": [
                    {"vpn": "openvpn", "country": "United States", "hostname": "us-1.expressnetw.com",
                     "ips": ["1.2.3.4", "5.6.7.8"]},
                    {"vpn": "openvpn", "country": "United Kingdom", "hostname": "uk-1.expressnetw.com",
                     "ips": ["9.10.11.12"]},
                ]
            }
        }
        provider = ExpressVPNProvider()
        provider.LOCAL_CACHE = "/nonexistent/cache.json"
        mock_resp = MagicMock()
        mock_resp.json.return_value = gluetun_resp
        mock_resp.raise_for_status = MagicMock()
        with patch("vpn_ip_intel.requests.get", return_value=mock_resp), \
             patch.object(BaseProvider, "shodan_org_search", return_value=set()):
            nodes = provider.fetch()
        assert len(nodes) == 3
        assert nodes[0]["ip"] == "1.2.3.4"
        assert nodes[0]["confidence"] == "confirmed"
        assert nodes[0]["source"] == "gluetun"
        assert nodes[0]["country"] == "US"  # Full name "United States" normalized to "US"
        assert nodes[2]["country"] == "GB"  # "United Kingdom" -> "GB"

    def test_fetch_falls_back_to_shodan(self):
        provider = ExpressVPNProvider()
        provider.LOCAL_CACHE = "/nonexistent/cache.json"
        provider.SEED_PATH = "/nonexistent/path.json"
        with patch("vpn_ip_intel.requests.get", side_effect=Exception("network error")), \
             patch.object(BaseProvider, "shodan_org_search", return_value={"9.9.9.9"}):
            nodes = provider.fetch()
        assert len(nodes) == 1
        assert nodes[0]["ip"] == "9.9.9.9"
        assert nodes[0]["source"] == "shodan_org"

    def test_fetch_with_local_cache(self, tmp_path):
        import json
        cache = tmp_path / "data.json"
        cache.write_text(json.dumps({
            "cachedModernRegionsList": {
                "regions": [
                    {"country": "US", "name": "USA", "test_ips": ["1.1.1.1", "2.2.2.2"]},
                    {"country": "GB", "name": "UK", "test_ips": ["3.3.3.3"]},
                ]
            }
        }))
        provider = ExpressVPNProvider()
        provider.LOCAL_CACHE = str(cache)
        provider.SEED_PATH = "/nonexistent"
        with patch("vpn_ip_intel.requests.get", side_effect=Exception("skip gluetun")), \
             patch.object(BaseProvider, "shodan_org_search", return_value=set()):
            nodes = provider.fetch()
        assert len(nodes) == 3
        assert nodes[0]["source"] == "expressvpn_local_cache"
        assert nodes[0]["country"] == "US"


class TestHotspotShieldProvider:
    """Test Hotspot Shield DNS + Shodan provider."""

    def test_provider_attributes(self):
        p = HotspotShieldProvider()
        assert p.name == "hotspotshield"
        assert "DPRK" in p.threat_relevance

    def test_fetch_dns_only(self):
        provider = HotspotShieldProvider()
        mock_run = MagicMock()
        mock_run.stdout = "1.2.3.4\n5.6.7.8\n"
        with patch("subprocess.run", return_value=mock_run), \
             patch.object(BaseProvider, "shodan_org_search", return_value=set()):
            nodes = provider.fetch()
        assert len(nodes) >= 1
        assert nodes[0]["server_type"] == "hydra"


class TestDNSEnumNewProviders:
    """Test new DNS enumeration providers have correct patterns."""

    def test_vyprvpn_generates_hostnames(self):
        p = VyprVPNProvider()
        hostnames = p._generate_hostnames()
        assert len(hostnames) > 100
        hosts = [h for h, _ in hostnames]
        assert "us1.vyprvpn.com" in hosts
        assert "jp1.vyprvpn.com" in hosts

    def test_flowvpn_generates_hostnames(self):
        p = FlowVPNProvider()
        hostnames = p._generate_hostnames()
        hosts = [h for h, _ in hostnames]
        assert "us.flow.host" in hosts
        assert "gb.flow.host" in hosts

    def test_njalla_generates_hostnames(self):
        p = NjallaVPNProvider()
        hostnames = p._generate_hostnames()
        assert len(hostnames) == 100
        hosts = [h for h, _ in hostnames]
        assert "wg001.njalla.no" in hosts
        assert "wg100.njalla.no" in hosts


import csv


def _write_test_csv(path, rows):
    """Helper to write a CSV file for testing."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _make_row(ip="1.2.3.4", provider="mullvad", ip_role="ingress", **overrides):
    """Helper to create a minimal row dict."""
    row = {"ip": ip, "provider": provider, "ip_role": ip_role}
    row.update(overrides)
    return row


class TestTemporalTracking:
    """Tests for first_seen/last_seen/active temporal tracking."""

    def test_fields_include_temporal_columns(self):
        assert "first_seen" in FIELDS
        assert "last_seen" in FIELDS
        assert "active" in FIELDS

    def test_load_existing_csv_missing_file(self, tmp_path):
        result = load_existing_csv(str(tmp_path / "nonexistent.csv"))
        assert result == {}

    def test_load_existing_csv_reads_rows(self, tmp_path):
        csv_path = str(tmp_path / "test.csv")
        _write_test_csv(csv_path, [
            _make_row("1.1.1.1", "mullvad", "ingress", first_seen="2026-01-01"),
            _make_row("2.2.2.2", "nord", "egress", first_seen="2026-02-01"),
        ])
        result = load_existing_csv(csv_path)
        assert len(result) == 2
        assert ("1.1.1.1", "mullvad", "ingress") in result
        assert ("2.2.2.2", "nord", "egress") in result

    def test_first_run_no_existing_csv(self, tmp_path):
        csv_path = str(tmp_path / "out.csv")
        fresh = [_make_row("1.1.1.1"), _make_row("2.2.2.2", provider="nord")]
        merged = merge_with_existing(fresh, csv_path, today="2026-05-06")
        assert len(merged) == 2
        for row in merged:
            assert row["first_seen"] == "2026-05-06"
            assert row["last_seen"] == "2026-05-06"
            assert row["active"] == "true"

    def test_existing_ip_preserves_first_seen(self, tmp_path):
        csv_path = str(tmp_path / "out.csv")
        _write_test_csv(csv_path, [
            _make_row("1.1.1.1", first_seen="2026-01-01", last_seen="2026-05-05", active="true"),
        ])
        fresh = [_make_row("1.1.1.1")]
        merged = merge_with_existing(fresh, csv_path, today="2026-05-06")
        assert len(merged) == 1
        assert merged[0]["first_seen"] == "2026-01-01"
        assert merged[0]["last_seen"] == "2026-05-06"
        assert merged[0]["active"] == "true"

    def test_disappeared_ip_retained(self, tmp_path):
        csv_path = str(tmp_path / "out.csv")
        _write_test_csv(csv_path, [
            _make_row("1.1.1.1", first_seen="2026-01-01", last_seen="2026-05-05", active="true"),
            _make_row("9.9.9.9", first_seen="2026-03-01", last_seen="2026-05-05", active="true"),
        ])
        fresh = [_make_row("1.1.1.1")]  # 9.9.9.9 disappeared
        merged = merge_with_existing(fresh, csv_path, today="2026-05-06")
        assert len(merged) == 2
        by_ip = {r["ip"]: r for r in merged}
        assert by_ip["1.1.1.1"]["active"] == "true"
        assert by_ip["9.9.9.9"]["active"] == "false"
        assert by_ip["9.9.9.9"]["first_seen"] == "2026-03-01"
        assert by_ip["9.9.9.9"]["last_seen"] == "2026-05-05"

    def test_new_ip_gets_today(self, tmp_path):
        csv_path = str(tmp_path / "out.csv")
        _write_test_csv(csv_path, [
            _make_row("1.1.1.1", first_seen="2026-01-01", last_seen="2026-05-05"),
        ])
        fresh = [_make_row("1.1.1.1"), _make_row("3.3.3.3")]
        merged = merge_with_existing(fresh, csv_path, today="2026-05-06")
        by_ip = {r["ip"]: r for r in merged}
        assert by_ip["3.3.3.3"]["first_seen"] == "2026-05-06"
        assert by_ip["3.3.3.3"]["last_seen"] == "2026-05-06"
        assert by_ip["3.3.3.3"]["active"] == "true"

    def test_merge_respects_dedup_key(self, tmp_path):
        csv_path = str(tmp_path / "out.csv")
        _write_test_csv(csv_path, [
            _make_row("1.1.1.1", ip_role="ingress", first_seen="2026-01-01", last_seen="2026-05-05"),
            _make_row("1.1.1.1", ip_role="egress", first_seen="2026-02-01", last_seen="2026-05-05"),
        ])
        fresh = [_make_row("1.1.1.1", ip_role="ingress")]  # egress role disappeared
        merged = merge_with_existing(fresh, csv_path, today="2026-05-06")
        assert len(merged) == 2
        by_role = {r["ip_role"]: r for r in merged}
        assert by_role["ingress"]["active"] == "true"
        assert by_role["ingress"]["first_seen"] == "2026-01-01"
        assert by_role["egress"]["active"] == "false"
        assert by_role["egress"]["first_seen"] == "2026-02-01"

    def test_historical_row_preserves_metadata(self, tmp_path):
        csv_path = str(tmp_path / "out.csv")
        _write_test_csv(csv_path, [
            _make_row("9.9.9.9", asn="AS1234", asn_name="TestASN",
                       first_seen="2026-01-01", last_seen="2026-05-05", active="true"),
        ])
        fresh = []  # IP disappeared
        merged = merge_with_existing(fresh, csv_path, today="2026-05-06")
        assert len(merged) == 1
        assert merged[0]["asn"] == "AS1234"
        assert merged[0]["asn_name"] == "TestASN"
        assert merged[0]["active"] == "false"

    def test_reappearing_ip(self, tmp_path):
        csv_path = str(tmp_path / "out.csv")
        _write_test_csv(csv_path, [
            _make_row("1.1.1.1", first_seen="2026-01-01", last_seen="2026-04-01", active="false"),
        ])
        fresh = [_make_row("1.1.1.1")]
        merged = merge_with_existing(fresh, csv_path, today="2026-05-06")
        assert len(merged) == 1
        assert merged[0]["active"] == "true"
        assert merged[0]["first_seen"] == "2026-01-01"
        assert merged[0]["last_seen"] == "2026-05-06"

    def test_backfill_on_upgrade(self, tmp_path):
        """Old CSV without temporal columns gets backfilled cleanly."""
        csv_path = str(tmp_path / "out.csv")
        # Write CSV without first_seen/last_seen columns (simulates pre-upgrade data)
        _write_test_csv(csv_path, [_make_row("1.1.1.1")])
        fresh = [_make_row("1.1.1.1")]
        merged = merge_with_existing(fresh, csv_path, today="2026-05-06")
        assert merged[0]["first_seen"] == "2026-05-06"
        assert merged[0]["last_seen"] == "2026-05-06"

    def test_backfill_disappeared_on_upgrade(self, tmp_path):
        """Disappeared IP from pre-upgrade CSV gets backfilled."""
        csv_path = str(tmp_path / "out.csv")
        _write_test_csv(csv_path, [_make_row("9.9.9.9")])
        fresh = []
        merged = merge_with_existing(fresh, csv_path, today="2026-05-06")
        assert merged[0]["first_seen"] == "2026-05-06"
        assert merged[0]["last_seen"] == "2026-05-06"
        assert merged[0]["active"] == "false"
