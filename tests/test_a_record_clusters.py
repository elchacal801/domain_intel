#!/usr/bin/env python3
"""Tests for A-record clustering functionality in build_frontend_data.py."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from build_frontend_data import (
    match_shared_provider,
    load_shared_infra_config,
    compute_a_record_cluster_confidence,
    compute_cluster_confidence,
    compute_clusters,
)


# ---------------------------------------------------------------------------
# Minimal config for unit tests (no YAML dependency)
# ---------------------------------------------------------------------------

def _build_minimal_config():
    """Build a minimal config dict for A-record testing."""
    return {
        "confidence_thresholds": {"high": 70, "medium": 40},
        "a_record_size_bonuses": [
            {"above": 100, "bonus": 30},
            {"above": 50, "bonus": 20},
            {"above": 20, "bonus": 15},
            {"above": 10, "bonus": 10},
            {"above": 5, "bonus": 5},
        ],
        "size_penalties": [
            {"above": 100, "penalty": 40},
            {"above": 50, "penalty": 30},
            {"above": 20, "penalty": 20},
            {"above": 10, "penalty": 10},
        ],
        "providers": {
            "cloudflare_cdn": {
                "label": "Cloudflare CDN",
                "category": "web_hosting",
                "asn_list": ["13335"],
                "_parsed_ip_ranges": [],
            },
        },
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_domain(domain, a_record="", a_record_asn="", a_record_asn_name="",
                 primary_mx="", mx_ip="", nameservers="", registrant_org=""):
    """Build a domain dict with fields used by clustering."""
    return {
        "domain": domain,
        "a_record": a_record,
        "a_record_asn": a_record_asn,
        "a_record_asn_name": a_record_asn_name,
        "primary_mx": primary_mx,
        "mx_ip": mx_ip,
        "nameservers": nameservers,
        "registrant_org": registrant_org,
    }


def _make_domains_dict(domain_list):
    """Convert a list of domain dicts to a domains dict keyed by domain name."""
    return {d["domain"]: d for d in domain_list}


# ---------------------------------------------------------------------------
# TestMatchSharedProviderASN
# ---------------------------------------------------------------------------

class TestMatchSharedProviderASN:
    """Test match_shared_provider() with value_type='asn'."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.config = _build_minimal_config()

    def test_match_shared_provider_asn_cloudflare(self):
        """ASN '13335' should match cloudflare_cdn provider."""
        result = match_shared_provider("13335", "asn", self.config)
        assert result is not None
        assert result[0] == "cloudflare_cdn"
        assert result[1] == "Cloudflare CDN"
        assert result[2] == "web_hosting"

    def test_match_shared_provider_asn_unknown(self):
        """ASN '99999' should not match any provider."""
        result = match_shared_provider("99999", "asn", self.config)
        assert result is None


# ---------------------------------------------------------------------------
# TestComputeARecordClusterConfidence
# ---------------------------------------------------------------------------

class TestComputeARecordClusterConfidence:
    """Test compute_a_record_cluster_confidence() inverted scoring logic."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.config = _build_minimal_config()

    def _make_all_domains(self, count, asn="12345", shared_asn=True):
        """Build domains dict with the given count, all sharing the same ASN."""
        domains = {}
        for i in range(count):
            name = f"d{i}.com"
            domains[name] = {
                "domain": name,
                "a_record_asn": asn if shared_asn else str(10000 + i),
            }
        return domains

    def test_a_record_confidence_large_unknown(self):
        """150 domains, no CDN match -> high confidence (>=70)."""
        names = [f"d{i}.com" for i in range(150)]
        all_domains = self._make_all_domains(150)

        score, level, breakdown = compute_a_record_cluster_confidence(
            cluster_size=150,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )
        assert score >= 70
        assert level == "high"

    def test_a_record_confidence_known_cdn(self):
        """150 domains, Cloudflare ASN match -> low confidence (<40)."""
        names = [f"d{i}.com" for i in range(150)]
        all_domains = self._make_all_domains(150)
        shared_match = ("cloudflare_cdn", "Cloudflare CDN", "web_hosting")

        score, level, breakdown = compute_a_record_cluster_confidence(
            cluster_size=150,
            shared_match=shared_match,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )
        assert score < 40
        assert level == "low"

    def test_a_record_confidence_small_unknown(self):
        """4 domains, no CDN match -> medium confidence (40-69)."""
        names = [f"d{i}.com" for i in range(4)]
        all_domains = self._make_all_domains(4)

        score, level, breakdown = compute_a_record_cluster_confidence(
            cluster_size=4,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )
        # base=50, no size bonus (4 is not above 5), homogeneity bonus=10 (all same ASN, >=3)
        # = 60, which is medium
        assert 40 <= score <= 69
        assert level == "medium"

    def test_a_record_confidence_inversion(self):
        """
        Same cluster: A-record score > MX score for large unknown clusters.
        Proves the inverted semantics: A-record rewards large unknown clusters
        while MX penalizes them.
        """
        count = 150
        names = [f"d{i}.com" for i in range(count)]
        all_domains = self._make_all_domains(count)

        a_score, _, _ = compute_a_record_cluster_confidence(
            cluster_size=count,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )

        mx_score, _, _ = compute_cluster_confidence(
            cluster_size=count,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )

        assert a_score > mx_score, (
            f"A-record score ({a_score}) should be higher than MX score ({mx_score}) "
            f"for large unknown clusters"
        )

    def test_a_record_confidence_homogeneity_bonus(self):
        """All domains same ASN, cluster >= 3, not shared -> bonus applied."""
        names = ["a.com", "b.com", "c.com"]
        all_domains = {
            name: {"domain": name, "a_record_asn": "12345"}
            for name in names
        }

        score_homo, _, breakdown_homo = compute_a_record_cluster_confidence(
            cluster_size=3,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )

        # Now with diverse ASNs (no bonus)
        all_domains_diverse = {
            name: {"domain": name, "a_record_asn": str(10000 + i)}
            for i, name in enumerate(names)
        }

        score_diverse, _, breakdown_diverse = compute_a_record_cluster_confidence(
            cluster_size=3,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains_diverse,
            config=self.config,
        )

        assert breakdown_homo["homogeneity"] > 0
        assert breakdown_diverse["homogeneity"] == 0
        assert score_homo > score_diverse

    def test_a_record_confidence_breakdown_structure(self):
        """Verify breakdown dict has keys: base, size, shared_infra, homogeneity."""
        names = ["a.com", "b.com", "c.com"]
        all_domains = {
            name: {"domain": name, "a_record_asn": "12345"}
            for name in names
        }

        score, level, breakdown = compute_a_record_cluster_confidence(
            cluster_size=3,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )

        expected_keys = {"base", "size", "shared_infra", "homogeneity"}
        assert expected_keys == set(breakdown.keys()), (
            f"Breakdown keys mismatch: expected {expected_keys}, got {set(breakdown.keys())}"
        )


# ---------------------------------------------------------------------------
# TestARecordClusterCompute
# ---------------------------------------------------------------------------

class TestARecordClusterCompute:
    """Test A-record clustering via compute_clusters()."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.config = _build_minimal_config()

    def test_a_record_cluster_created(self):
        """3+ domains with same a_record produce an a_record_ip node."""
        domains = _make_domains_dict([
            _make_domain("a.com", a_record="192.0.2.1", a_record_asn="12345",
                         a_record_asn_name="Evil Hosting"),
            _make_domain("b.com", a_record="192.0.2.1", a_record_asn="12345",
                         a_record_asn_name="Evil Hosting"),
            _make_domain("c.com", a_record="192.0.2.1", a_record_asn="12345",
                         a_record_asn_name="Evil Hosting"),
        ])

        result = compute_clusters(domains, min_cluster_size=3,
                                  shared_infra_config=self.config)

        a_record_nodes = [n for n in result["nodes"] if n["type"] == "a_record_ip"]
        assert len(a_record_nodes) == 1
        assert a_record_nodes[0]["label"] == "192.0.2.1"
        assert a_record_nodes[0]["domain_count"] == 3

    def test_a_record_cluster_has_hosting_asn(self):
        """A-record cluster node carries hosting_asn and hosting_asn_name."""
        domains = _make_domains_dict([
            _make_domain("a.com", a_record="192.0.2.1", a_record_asn="12345",
                         a_record_asn_name="Evil Hosting"),
            _make_domain("b.com", a_record="192.0.2.1", a_record_asn="12345",
                         a_record_asn_name="Evil Hosting"),
            _make_domain("c.com", a_record="192.0.2.1", a_record_asn="12345",
                         a_record_asn_name="Evil Hosting"),
        ])

        result = compute_clusters(domains, min_cluster_size=3,
                                  shared_infra_config=self.config)

        a_record_nodes = [n for n in result["nodes"] if n["type"] == "a_record_ip"]
        assert len(a_record_nodes) == 1
        node = a_record_nodes[0]
        assert "hosting_asn" in node
        assert node["hosting_asn"] == "12345"
        assert "hosting_asn_name" in node
        assert node["hosting_asn_name"] == "Evil Hosting"

    def test_a_record_cluster_resolution_method(self):
        """A-record cluster node has resolution_method == 'a_record'."""
        domains = _make_domains_dict([
            _make_domain("a.com", a_record="192.0.2.1", a_record_asn="12345"),
            _make_domain("b.com", a_record="192.0.2.1", a_record_asn="12345"),
            _make_domain("c.com", a_record="192.0.2.1", a_record_asn="12345"),
        ])

        result = compute_clusters(domains, min_cluster_size=3,
                                  shared_infra_config=self.config)

        a_record_nodes = [n for n in result["nodes"] if n["type"] == "a_record_ip"]
        assert len(a_record_nodes) == 1
        assert a_record_nodes[0]["resolution_method"] == "a_record"


# ---------------------------------------------------------------------------
# TestARecordResolutionChain
# ---------------------------------------------------------------------------

class TestARecordResolutionChain:
    """Test that A-record resolution chains are added to domain records."""

    def test_a_record_chain_added(self, tmp_path):
        """Domain with a_record gets a_record_chain in output via build_outputs."""
        import csv
        import json
        from build_frontend_data import build_outputs

        probed_headers = [
            "domain", "primary_mx", "mx_ip", "asn", "asn_name", "bgp_prefix",
            "cc", "registry", "mx_records", "nameservers", "risk_tags", "error",
            "rbl_hits", "creation_date", "age_days", "otx_risk", "registrant_org",
            "http_status", "http_title", "http_server", "https_status",
            "https_title", "https_server", "http_redirect_status",
            "http_redirect_target", "flame_tp_ids", "gleif_lei", "gleif_status",
            "gleif_legal_name", "gleif_jurisdiction", "gleif_has_parent",
            "os_match_score", "os_entity_type", "os_dataset", "os_entity_id",
            "icij_match_score", "icij_entity_match", "icij_dataset",
            "icij_jurisdiction", "dnstwist_match", "dnstwist_fuzzer",
            "dnstwist_target", "redirects_to_brand", "registrant_mismatch",
            "ssl_present", "a_record", "a_record_asn", "a_record_asn_name",
        ]

        probed_path = tmp_path / "probed.csv"
        fp_path = tmp_path / "fp.csv"
        output_dir = tmp_path / "output"

        # Write probed CSV with a_record
        defaults = {h: "" for h in probed_headers}
        defaults["domain"] = "test.com"
        defaults["a_record"] = "192.0.2.1"
        defaults["a_record_asn"] = "12345"
        defaults["a_record_asn_name"] = "Test Hosting"

        with open(str(probed_path), "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(probed_headers)
            writer.writerow([defaults[h] for h in probed_headers])

        # Write empty fingerprints CSV
        with open(str(fp_path), "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["domain", "fp_id", "fp_name", "confidence",
                             "flame_tp_ids", "evidence"])

        build_outputs(
            probed_path=str(probed_path),
            fingerprints_path=str(fp_path),
            output_dir=str(output_dir),
            min_cluster_size=3,
            optional_files={},
        )

        # Collect domain data from shard files
        all_domains = {}
        for fname in os.listdir(str(output_dir)):
            if fname.startswith("domains_") and fname.endswith(".json"):
                with open(os.path.join(str(output_dir), fname), "r") as f:
                    all_domains.update(json.load(f))

        assert "test.com" in all_domains
        chain = all_domains["test.com"].get("a_record_chain")
        assert chain is not None, "Domain with a_record should have a_record_chain"
        assert "path" in chain
        assert "web_provider" in chain
        assert "web_provider_label" in chain
        assert "web_shared" in chain
        assert chain["path"] == ["test.com", "A", "192.0.2.1"]


# ---------------------------------------------------------------------------
# TestBackwardCompatibility
# ---------------------------------------------------------------------------

class TestBackwardCompatibility:
    """Test backward compatibility when domains lack A-record data."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.config = _build_minimal_config()

    def test_backward_compat_no_a_record(self):
        """Domains without a_record should not crash or produce A-record clusters."""
        domains = _make_domains_dict([
            _make_domain("a.com", primary_mx="mx.test.com", mx_ip="1.2.3.4"),
            _make_domain("b.com", primary_mx="mx.test.com", mx_ip="1.2.3.4"),
            _make_domain("c.com", primary_mx="mx.test.com", mx_ip="1.2.3.4"),
        ])

        result = compute_clusters(domains, min_cluster_size=3,
                                  shared_infra_config=self.config)

        a_record_nodes = [n for n in result["nodes"] if n["type"] == "a_record_ip"]
        assert len(a_record_nodes) == 0, (
            "Domains without a_record should not produce A-record clusters"
        )

        # MX cluster should still work
        mx_nodes = [n for n in result["nodes"] if n["type"] == "mx_host"]
        assert len(mx_nodes) == 1
