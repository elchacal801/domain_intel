#!/usr/bin/env python3
"""Tests for shared infrastructure matching and confidence scoring in build_frontend_data.py."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from build_frontend_data import (
    load_shared_infra_config,
    match_shared_provider,
    compute_cluster_confidence,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

REAL_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'config', 'shared_infrastructure.yaml',
)


def _build_minimal_config():
    """Build a minimal config dict with parsed IP ranges for testing."""
    import ipaddress
    config = {
        "confidence_thresholds": {"high": 70, "medium": 40},
        "size_penalties": [
            {"above": 100, "penalty": 40},
            {"above": 50, "penalty": 30},
            {"above": 20, "penalty": 20},
            {"above": 10, "penalty": 10},
        ],
        "providers": {
            "cloudflare_email_routing": {
                "label": "Cloudflare Email Routing",
                "category": "email",
                "mx_patterns": ["route*.mx.cloudflare.net"],
                "ip_ranges": ["162.159.205.0/24"],
                "_parsed_ip_ranges": [
                    ipaddress.ip_network("162.159.205.0/24", strict=False),
                ],
            },
            "google_workspace": {
                "label": "Google Workspace",
                "category": "email",
                "mx_patterns": [
                    "aspmx.l.google.com",
                    "alt*.aspmx.l.google.com",
                    "*.googlemail.com",
                ],
                "_parsed_ip_ranges": [],
            },
            "microsoft_365": {
                "label": "Microsoft 365",
                "category": "email",
                "mx_patterns": ["*.mail.protection.outlook.com"],
                "_parsed_ip_ranges": [],
            },
            "improvmx": {
                "label": "ImprovMX",
                "category": "email",
                "mx_patterns": ["mx1.improvmx.com", "mx2.improvmx.com"],
                "_parsed_ip_ranges": [],
            },
            "cloudflare_ns": {
                "label": "Cloudflare DNS",
                "category": "dns",
                "ns_patterns": ["*.ns.cloudflare.com"],
                "_parsed_ip_ranges": [],
            },
            "aws_route53": {
                "label": "AWS Route 53",
                "category": "dns",
                "ns_patterns": ["ns-*.awsdns-*"],
                "_parsed_ip_ranges": [],
            },
        },
    }
    return config


# ---------------------------------------------------------------------------
# TestMatchSharedProvider
# ---------------------------------------------------------------------------

class TestMatchSharedProvider:
    """Test match_shared_provider() against various MX, IP, and NS values."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.config = _build_minimal_config()

    # --- MX matching ---

    def test_match_mx_cloudflare(self):
        result = match_shared_provider("route1.mx.cloudflare.net", "mx", self.config)
        assert result is not None
        assert result[0] == "cloudflare_email_routing"

    def test_match_mx_cloudflare_route2(self):
        result = match_shared_provider("route2.mx.cloudflare.net", "mx", self.config)
        assert result is not None
        assert result[0] == "cloudflare_email_routing"

    def test_match_mx_google(self):
        result = match_shared_provider("aspmx.l.google.com", "mx", self.config)
        assert result is not None
        assert result[0] == "google_workspace"

    def test_match_mx_google_alt(self):
        result = match_shared_provider("alt1.aspmx.l.google.com", "mx", self.config)
        assert result is not None
        assert result[0] == "google_workspace"

    def test_match_mx_microsoft(self):
        result = match_shared_provider(
            "example-com.mail.protection.outlook.com", "mx", self.config,
        )
        assert result is not None
        assert result[0] == "microsoft_365"

    def test_match_mx_improvmx(self):
        result = match_shared_provider("mx1.improvmx.com", "mx", self.config)
        assert result is not None
        assert result[0] == "improvmx"

    def test_match_mx_unknown(self):
        result = match_shared_provider("mail.shadyhost.ru", "mx", self.config)
        assert result is None

    def test_match_mx_empty(self):
        result = match_shared_provider("", "mx", self.config)
        assert result is None

    def test_match_mx_case_insensitive(self):
        result = match_shared_provider("ROUTE1.MX.CLOUDFLARE.NET", "mx", self.config)
        assert result is not None
        assert result[0] == "cloudflare_email_routing"

    # --- IP matching ---

    def test_match_ip_cloudflare_in_range(self):
        result = match_shared_provider("162.159.205.13", "ip", self.config)
        assert result is not None
        assert result[0] == "cloudflare_email_routing"

    def test_match_ip_outside_range(self):
        result = match_shared_provider("1.2.3.4", "ip", self.config)
        assert result is None

    def test_match_ip_invalid(self):
        result = match_shared_provider("not-an-ip", "ip", self.config)
        assert result is None

    # --- NS matching ---

    def test_match_ns_cloudflare(self):
        result = match_shared_provider("a.ns.cloudflare.com", "ns", self.config)
        assert result is not None
        assert result[0] == "cloudflare_ns"

    def test_match_ns_route53(self):
        result = match_shared_provider("ns-123.awsdns-45.org", "ns", self.config)
        assert result is not None
        assert result[0] == "aws_route53"

    def test_match_ns_unknown(self):
        result = match_shared_provider("ns1.customdns.com", "ns", self.config)
        assert result is None


# ---------------------------------------------------------------------------
# TestComputeClusterConfidence
# ---------------------------------------------------------------------------

class TestComputeClusterConfidence:
    """Test compute_cluster_confidence() scoring logic."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.config = _build_minimal_config()

    def _make_domains(self, names, same_asn=True):
        """Build a simple domains dict. When same_asn=True all share ASN 12345."""
        domains = {}
        for i, name in enumerate(names):
            domains[name] = {
                "domain": name,
                "asn": "12345" if same_asn else str(10000 + i),
            }
        return domains

    def test_confidence_small_dedicated(self):
        """3 domains, no shared match, same ASN -> high confidence (>=70)."""
        names = ["a.com", "b.com", "c.com"]
        all_domains = self._make_domains(names, same_asn=True)
        score, level, breakdown = compute_cluster_confidence(
            cluster_size=3,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )
        assert score >= 70
        assert level == "high"

    def test_confidence_large_shared(self):
        """940 domains with a shared match -> low confidence (<40)."""
        names = [f"d{i}.com" for i in range(940)]
        all_domains = self._make_domains(names, same_asn=True)
        shared_match = ("cloudflare_email_routing", "Cloudflare Email Routing", "email")
        score, level, breakdown = compute_cluster_confidence(
            cluster_size=940,
            shared_match=shared_match,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )
        assert score < 40
        assert level == "low"

    def test_confidence_medium_cluster(self):
        """25 domains, no shared match, same ASN -> medium confidence (40-69)."""
        names = [f"d{i}.com" for i in range(25)]
        all_domains = self._make_domains(names, same_asn=True)
        score, level, breakdown = compute_cluster_confidence(
            cluster_size=25,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )
        # base 80 - size_penalty 20 (above 20) = 60 -> medium
        assert 40 <= score <= 69
        assert level == "medium"

    def test_confidence_shared_penalty(self):
        """Same cluster with and without shared match — shared should score lower."""
        names = ["a.com", "b.com", "c.com"]
        all_domains = self._make_domains(names, same_asn=True)
        shared_match = ("improvmx", "ImprovMX", "email")

        score_shared, _, _ = compute_cluster_confidence(
            cluster_size=3,
            shared_match=shared_match,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )
        score_dedicated, _, _ = compute_cluster_confidence(
            cluster_size=3,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )
        assert score_shared < score_dedicated

    def test_confidence_asn_diversity_penalty(self):
        """High ASN diversity (>0.7 ratio) should reduce score."""
        names = ["a.com", "b.com", "c.com"]
        # Each domain has a different ASN -> ratio = 3/3 = 1.0 > 0.7
        all_domains = self._make_domains(names, same_asn=False)

        score_diverse, _, breakdown_diverse = compute_cluster_confidence(
            cluster_size=3,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )
        # Same cluster with identical ASN
        all_domains_same = self._make_domains(names, same_asn=True)
        score_same, _, breakdown_same = compute_cluster_confidence(
            cluster_size=3,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains_same,
            config=self.config,
        )
        assert score_diverse < score_same
        assert breakdown_diverse["diversity_penalty"] < 0

    def test_confidence_uniqueness_bonus(self):
        """With uniqueness_bonus=10 should increase score by 10."""
        names = ["a.com", "b.com", "c.com"]
        all_domains = self._make_domains(names, same_asn=True)

        score_no_bonus, _, _ = compute_cluster_confidence(
            cluster_size=3,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
            uniqueness_bonus=0,
        )
        score_with_bonus, _, _ = compute_cluster_confidence(
            cluster_size=3,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
            uniqueness_bonus=10,
        )
        assert score_with_bonus == score_no_bonus + 10

    def test_confidence_breakdown_structure(self):
        """Verify breakdown dict has the expected keys."""
        names = ["a.com", "b.com", "c.com"]
        all_domains = self._make_domains(names, same_asn=True)
        score, level, breakdown = compute_cluster_confidence(
            cluster_size=3,
            shared_match=None,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )
        expected_keys = {
            "base", "size_penalty", "shared_penalty",
            "diversity_penalty", "uniqueness_bonus",
            "cluster_size", "unique_asns",
        }
        assert expected_keys.issubset(set(breakdown.keys()))

    def test_confidence_score_clamped(self):
        """Extreme inputs should not produce scores <0 or >100."""
        names = [f"d{i}.com" for i in range(2000)]
        all_domains = self._make_domains(names, same_asn=False)
        shared_match = ("cloudflare_email_routing", "Cloudflare Email Routing", "email")

        # Maximally penalised cluster
        score_low, _, _ = compute_cluster_confidence(
            cluster_size=2000,
            shared_match=shared_match,
            domains_in_cluster=set(names),
            all_domains=all_domains,
            config=self.config,
        )
        assert 0 <= score_low <= 100

        # Maximally boosted cluster
        names_small = ["a.com", "b.com", "c.com"]
        all_domains_small = self._make_domains(names_small, same_asn=True)
        score_high, _, _ = compute_cluster_confidence(
            cluster_size=3,
            shared_match=None,
            domains_in_cluster=set(names_small),
            all_domains=all_domains_small,
            config=self.config,
            uniqueness_bonus=50,
        )
        assert 0 <= score_high <= 100


# ---------------------------------------------------------------------------
# TestLoadSharedInfraConfig
# ---------------------------------------------------------------------------

class TestLoadSharedInfraConfig:
    """Test load_shared_infra_config() loading and parsing."""

    def test_config_loads_from_real_file(self):
        config = load_shared_infra_config(REAL_CONFIG_PATH)
        assert isinstance(config, dict)
        assert "providers" in config
        assert "confidence_thresholds" in config

    def test_config_has_providers(self):
        config = load_shared_infra_config(REAL_CONFIG_PATH)
        assert len(config["providers"]) > 0

    def test_config_has_parsed_ip_ranges(self):
        config = load_shared_infra_config(REAL_CONFIG_PATH)
        provider = config["providers"]["cloudflare_email_routing"]
        assert "_parsed_ip_ranges" in provider
        assert len(provider["_parsed_ip_ranges"]) > 0

    def test_config_missing_file(self, tmp_path):
        config = load_shared_infra_config(str(tmp_path / "nonexistent.yaml"))
        assert config == {}

    def test_config_has_thresholds(self):
        config = load_shared_infra_config(REAL_CONFIG_PATH)
        thresholds = config["confidence_thresholds"]
        assert "high" in thresholds
        assert "medium" in thresholds
