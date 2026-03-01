#!/usr/bin/env python3
"""Integration tests for enhanced cluster computation in build_frontend_data.py."""

import csv
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from build_frontend_data import (
    compute_clusters,
    compute_stats,
    build_outputs,
    load_shared_infra_config,
    match_shared_provider,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REAL_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'config', 'shared_infrastructure.yaml',
)

PROBED_HEADERS = [
    "domain", "primary_mx", "mx_ip", "asn", "asn_name", "bgp_prefix", "cc",
    "registry", "mx_records", "nameservers", "risk_tags", "error", "rbl_hits",
    "creation_date", "age_days", "otx_risk", "registrant_org", "http_status",
    "http_title", "http_server", "https_status", "https_title", "https_server",
    "http_redirect_status", "http_redirect_target", "flame_tp_ids", "gleif_lei",
    "gleif_status", "gleif_legal_name", "gleif_jurisdiction", "gleif_has_parent",
    "os_match_score", "os_entity_type", "os_dataset", "os_entity_id",
    "icij_match_score", "icij_entity_match", "icij_dataset", "icij_jurisdiction",
    "dnstwist_match", "dnstwist_fuzzer", "dnstwist_target", "redirects_to_brand",
    "registrant_mismatch", "ssl_present",
]

FP_HEADERS = ["domain", "fp_id", "fp_name", "confidence", "flame_tp_ids", "evidence"]


def write_csv(path, headers, rows):
    """Helper to write a test CSV file."""
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for row in rows:
            writer.writerow(row)


def _probed_row(domain="evil.com", primary_mx="mx.evil.com", mx_ip="1.2.3.4",
                asn="16276", nameservers="ns1.evil.com", registrant_org="Evil Corp",
                **overrides):
    """Build a probed CSV row as a list matching PROBED_HEADERS."""
    defaults = {h: "" for h in PROBED_HEADERS}
    defaults.update({
        "domain": domain,
        "primary_mx": primary_mx,
        "mx_ip": mx_ip,
        "asn": asn,
        "nameservers": nameservers,
        "registrant_org": registrant_org,
    })
    defaults.update(overrides)
    return [defaults[h] for h in PROBED_HEADERS]


def _make_domains(specs):
    """Build a domains dict from a list of (domain, primary_mx, mx_ip, asn, registrant_org, nameservers) tuples."""
    domains = {}
    for spec in specs:
        d, mx, ip, asn, reg, ns = spec
        domains[d] = {
            "domain": d,
            "primary_mx": mx,
            "mx_ip": ip,
            "asn": asn,
            "registrant_org": reg,
            "nameservers": ns,
        }
    return domains


@pytest.fixture(scope="module")
def shared_config():
    """Load the real shared_infrastructure.yaml once for the module."""
    return load_shared_infra_config(REAL_CONFIG_PATH)


# ---------------------------------------------------------------------------
# TestEnhancedClusterNodes
# ---------------------------------------------------------------------------

class TestEnhancedClusterNodes:
    """Verify that enhanced cluster nodes carry shared-infra metadata."""

    def test_enhanced_cluster_nodes_have_metadata(self, shared_config):
        """Build clusters with shared_infra_config, verify infra nodes have required fields."""
        domains = _make_domains([
            ("a.com", "route1.mx.cloudflare.net", "1.1.1.1", "111", "Org", "ns1.a.com"),
            ("b.com", "route1.mx.cloudflare.net", "2.2.2.2", "222", "Org", "ns1.b.com"),
            ("c.com", "route1.mx.cloudflare.net", "3.3.3.3", "333", "Org", "ns1.c.com"),
        ])
        result = compute_clusters(domains, min_cluster_size=3,
                                  shared_infra_config=shared_config)
        infra_nodes = [n for n in result["nodes"] if n["type"] != "domain"]
        assert len(infra_nodes) >= 1

        for node in infra_nodes:
            assert "shared_infra" in node
            assert "provider" in node
            assert "confidence" in node
            assert "confidence_level" in node
            assert "confidence_breakdown" in node
            assert "resolution_method" in node
            assert "domain_count" in node

    def test_shared_infra_cluster_tagged(self, shared_config):
        """Domains sharing Cloudflare MX -> cluster tagged shared_infra=True."""
        domains = _make_domains([
            ("a.com", "route1.mx.cloudflare.net", "1.1.1.1", "111", "Org", "ns1.a.com"),
            ("b.com", "route1.mx.cloudflare.net", "2.2.2.2", "222", "Org", "ns1.b.com"),
            ("c.com", "route1.mx.cloudflare.net", "3.3.3.3", "333", "Org", "ns1.c.com"),
        ])
        result = compute_clusters(domains, min_cluster_size=3,
                                  shared_infra_config=shared_config)
        mx_nodes = [n for n in result["nodes"] if n["type"] == "mx_host"]
        assert len(mx_nodes) == 1
        mx_node = mx_nodes[0]
        assert mx_node["shared_infra"] is True
        assert mx_node["provider"] == "cloudflare_email_routing"

    def test_dedicated_infra_not_tagged(self, shared_config):
        """Domains sharing an unknown MX -> shared_infra=False, provider=None."""
        domains = _make_domains([
            ("a.com", "mail.customserver.com", "1.1.1.1", "111", "Org", "ns1.a.com"),
            ("b.com", "mail.customserver.com", "2.2.2.2", "222", "Org", "ns1.b.com"),
            ("c.com", "mail.customserver.com", "3.3.3.3", "333", "Org", "ns1.c.com"),
        ])
        result = compute_clusters(domains, min_cluster_size=3,
                                  shared_infra_config=shared_config)
        mx_nodes = [n for n in result["nodes"] if n["type"] == "mx_host"]
        assert len(mx_nodes) == 1
        mx_node = mx_nodes[0]
        assert mx_node["shared_infra"] is False
        assert mx_node["provider"] is None


# ---------------------------------------------------------------------------
# TestResolutionChain
# ---------------------------------------------------------------------------

class TestResolutionChain:
    """Verify resolution chain enrichment on domain records via build_outputs."""

    def _setup_and_build(self, tmp_path, rows):
        """Write CSVs, run build_outputs, and return parsed domain shard data."""
        probed_path = tmp_path / "probed.csv"
        fp_path = tmp_path / "fp.csv"
        output_dir = tmp_path / "output"

        write_csv(probed_path, PROBED_HEADERS, rows)
        write_csv(fp_path, FP_HEADERS, [])

        build_outputs(
            probed_path=str(probed_path),
            fingerprints_path=str(fp_path),
            output_dir=str(output_dir),
            min_cluster_size=3,
            optional_files={},
        )

        # Collect all domain records from shard files
        all_domains = {}
        for fname in os.listdir(str(output_dir)):
            if fname.startswith("domains_") and fname.endswith(".json"):
                with open(os.path.join(str(output_dir), fname), "r") as f:
                    all_domains.update(json.load(f))
        return all_domains

    def test_resolution_chain_added_to_domains(self, tmp_path):
        """Domain records with primary_mx should have resolution_chain."""
        rows = [
            _probed_row(domain="a.com", primary_mx="mx.test.com", mx_ip="1.2.3.4"),
        ]
        domains = self._setup_and_build(tmp_path, rows)
        chain = domains["a.com"].get("resolution_chain")
        assert chain is not None
        assert "path" in chain
        assert "mx_provider" in chain
        assert "mx_provider_label" in chain
        assert "mx_shared" in chain

    def test_resolution_chain_shared_provider(self, tmp_path):
        """Domain with route1.mx.cloudflare.net should be tagged as shared."""
        rows = [
            _probed_row(domain="a.com", primary_mx="route1.mx.cloudflare.net",
                        mx_ip="162.159.205.13"),
        ]
        domains = self._setup_and_build(tmp_path, rows)
        chain = domains["a.com"]["resolution_chain"]
        assert chain["mx_shared"] is True
        assert chain["mx_provider"] == "cloudflare_email_routing"

    def test_resolution_chain_not_added_without_mx(self, tmp_path):
        """Domain with no primary_mx should not have resolution_chain."""
        rows = [
            _probed_row(domain="nomx.com", primary_mx="", mx_ip=""),
        ]
        domains = self._setup_and_build(tmp_path, rows)
        assert "resolution_chain" not in domains["nomx.com"]


# ---------------------------------------------------------------------------
# TestStatsConfidenceDistribution
# ---------------------------------------------------------------------------

class TestStatsConfidenceDistribution:
    """Verify stats include cluster confidence distribution."""

    def test_stats_include_confidence_distribution(self, shared_config):
        """Stats dict should have cluster_confidence_distribution and shared_infra_clusters."""
        domains = _make_domains([
            ("a.com", "route1.mx.cloudflare.net", "1.1.1.1", "111", "Org", "ns1.a.com"),
            ("b.com", "route1.mx.cloudflare.net", "2.2.2.2", "222", "Org", "ns1.b.com"),
            ("c.com", "route1.mx.cloudflare.net", "3.3.3.3", "333", "Org", "ns1.c.com"),
        ])
        clusters = compute_clusters(domains, min_cluster_size=3,
                                    shared_infra_config=shared_config)
        stats = compute_stats(domains, {}, clusters)

        assert "cluster_confidence_distribution" in stats
        dist = stats["cluster_confidence_distribution"]
        assert "high" in dist
        assert "medium" in dist
        assert "low" in dist

        assert "shared_infra_clusters" in stats
        assert isinstance(stats["shared_infra_clusters"], int)


# ---------------------------------------------------------------------------
# TestIPClusterRelatedMX
# ---------------------------------------------------------------------------

class TestIPClusterRelatedMX:
    """Verify IP cluster nodes include related_mx_hosts."""

    def test_ip_cluster_has_related_mx_hosts(self, shared_config):
        """IP cluster node should carry a related_mx_hosts list."""
        domains = _make_domains([
            ("a.com", "mx1.test.com", "10.0.0.1", "111", "Org", "ns1.a.com"),
            ("b.com", "mx2.test.com", "10.0.0.1", "222", "Org", "ns1.b.com"),
            ("c.com", "mx1.test.com", "10.0.0.1", "333", "Org", "ns1.c.com"),
        ])
        result = compute_clusters(domains, min_cluster_size=3,
                                  shared_infra_config=shared_config)
        ip_nodes = [n for n in result["nodes"] if n["type"] == "ip"]
        assert len(ip_nodes) == 1
        ip_node = ip_nodes[0]
        assert "related_mx_hosts" in ip_node
        assert isinstance(ip_node["related_mx_hosts"], list)
        assert "mx1.test.com" in ip_node["related_mx_hosts"]
        assert "mx2.test.com" in ip_node["related_mx_hosts"]


# ---------------------------------------------------------------------------
# TestClusterResolutionMethods
# ---------------------------------------------------------------------------

class TestClusterResolutionMethods:
    """Verify resolution_method values on different cluster types."""

    def test_cluster_resolution_methods(self, shared_config):
        """MX -> mx_host, IP -> mx_ip, registrar+NS -> registration."""
        domains = _make_domains([
            # Shared MX host
            ("a.com", "mx.shared.com", "1.1.1.1", "111", "Evil Corp", "ns1.evil.com;ns2.evil.com"),
            ("b.com", "mx.shared.com", "2.2.2.2", "222", "Evil Corp", "ns1.evil.com;ns2.evil.com"),
            ("c.com", "mx.shared.com", "3.3.3.3", "333", "Evil Corp", "ns1.evil.com;ns2.evil.com"),
            # Shared IP
            ("d.com", "mx1.d.com", "10.0.0.1", "444", "Org2", "ns1.d.com"),
            ("e.com", "mx1.e.com", "10.0.0.1", "555", "Org2", "ns1.e.com"),
            ("f.com", "mx1.f.com", "10.0.0.1", "666", "Org2", "ns1.f.com"),
        ])
        result = compute_clusters(domains, min_cluster_size=3,
                                  shared_infra_config=shared_config)

        mx_nodes = [n for n in result["nodes"] if n["type"] == "mx_host"]
        for node in mx_nodes:
            assert node["resolution_method"] == "mx_host"

        ip_nodes = [n for n in result["nodes"] if n["type"] == "ip"]
        for node in ip_nodes:
            assert node["resolution_method"] == "mx_ip"

        rns_nodes = [n for n in result["nodes"] if n["type"] == "registrar_ns"]
        for node in rns_nodes:
            assert node["resolution_method"] == "registration"
