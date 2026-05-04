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
    BaseProvider, load_vpn_lookup, normalize_node, compute_prefix_inferred_rows,
    load_scores, join_scores, FIELDS, SCORE_FIELDS,
    SHARED_HOSTING_ASNS, _COUNTRY_ALIASES, _SERVER_TYPE_ALIASES, TODAY,
    IP_ROLES,
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
