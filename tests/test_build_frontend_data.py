#!/usr/bin/env python3
"""Tests for build_frontend_data.py — data transformer for the investigation frontend."""

import csv
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from build_frontend_data import (
    load_probed_csv,
    load_fingerprint_matches,
    load_optional_csv,
    merge_optional_data,
    compute_clusters,
    compute_stats,
    build_outputs,
    compute_risk_score,
    build_infra_index,
    _safe_float,
)


# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------

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
    """Build a probed CSV row dict, then return as a list matching PROBED_HEADERS."""
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


# ---------------------------------------------------------------------------
# TestLoadProbedCSV
# ---------------------------------------------------------------------------

class TestLoadProbedCSV:
    """Test loading the probed domains CSV."""

    def test_loads_rows_keyed_by_domain(self, tmp_path):
        csv_path = tmp_path / "probed.csv"
        write_csv(csv_path, PROBED_HEADERS, [
            _probed_row(domain="evil.com", asn="16276"),
            _probed_row(domain="bad.net", asn="99999"),
        ])
        result = load_probed_csv(str(csv_path))
        assert len(result) == 2
        assert "evil.com" in result
        assert "bad.net" in result
        assert result["evil.com"]["asn"] == "16276"
        assert result["bad.net"]["asn"] == "99999"

    def test_returns_empty_dict_for_missing_file(self, tmp_path):
        result = load_probed_csv(str(tmp_path / "nonexistent.csv"))
        assert result == {}

    def test_returns_empty_dict_for_empty_csv(self, tmp_path):
        csv_path = tmp_path / "empty.csv"
        write_csv(csv_path, PROBED_HEADERS, [])
        result = load_probed_csv(str(csv_path))
        assert result == {}

    def test_all_columns_present_in_row(self, tmp_path):
        csv_path = tmp_path / "probed.csv"
        write_csv(csv_path, PROBED_HEADERS, [
            _probed_row(domain="test.com", primary_mx="mx.test.com", cc="US"),
        ])
        result = load_probed_csv(str(csv_path))
        row = result["test.com"]
        assert row["primary_mx"] == "mx.test.com"
        assert row["cc"] == "US"
        assert row["domain"] == "test.com"


# ---------------------------------------------------------------------------
# TestLoadFingerprintMatches
# ---------------------------------------------------------------------------

class TestLoadFingerprintMatches:
    """Test loading and grouping fingerprint matches by domain."""

    def test_loads_and_groups_by_domain(self, tmp_path):
        csv_path = tmp_path / "fp.csv"
        write_csv(csv_path, FP_HEADERS, [
            ["evil.com", "FP-001", "Test FP", "85", "TP-0001", "asn=16276"],
            ["evil.com", "FP-002", "Other FP", "70", "TP-0002", "cc=FR"],
            ["bad.net", "FP-001", "Test FP", "80", "TP-0001", "asn=16276"],
        ])
        result = load_fingerprint_matches(str(csv_path))
        assert len(result) == 2
        assert len(result["evil.com"]) == 2
        assert len(result["bad.net"]) == 1
        assert result["evil.com"][0]["fp_id"] == "FP-001"
        assert result["evil.com"][1]["fp_id"] == "FP-002"

    def test_returns_empty_dict_for_missing_file(self, tmp_path):
        result = load_fingerprint_matches(str(tmp_path / "nonexistent.csv"))
        assert result == {}

    def test_returns_empty_dict_for_empty_csv(self, tmp_path):
        csv_path = tmp_path / "fp.csv"
        write_csv(csv_path, FP_HEADERS, [])
        result = load_fingerprint_matches(str(csv_path))
        assert result == {}

    def test_match_dict_has_expected_keys(self, tmp_path):
        csv_path = tmp_path / "fp.csv"
        write_csv(csv_path, FP_HEADERS, [
            ["evil.com", "FP-001", "Test FP", "85", "TP-0001", "asn=16276"],
        ])
        result = load_fingerprint_matches(str(csv_path))
        match = result["evil.com"][0]
        assert match["fp_id"] == "FP-001"
        assert match["fp_name"] == "Test FP"
        assert match["confidence"] == "85"
        assert match["flame_tp_ids"] == "TP-0001"
        assert match["evidence"] == "asn=16276"


# ---------------------------------------------------------------------------
# TestLoadOptionalCSV
# ---------------------------------------------------------------------------

class TestLoadOptionalCSV:
    """Test loading optional enrichment CSVs."""

    def test_loads_csv_keyed_by_domain(self, tmp_path):
        csv_path = tmp_path / "ai_class.csv"
        write_csv(csv_path, ["domain", "category", "confidence"], [
            ["evil.com", "Phishing", "High"],
            ["bad.net", "Legitimate", "Medium"],
        ])
        result = load_optional_csv(str(csv_path), ["category", "confidence"])
        assert len(result) == 2
        assert result["evil.com"]["category"] == "Phishing"
        assert result["evil.com"]["confidence"] == "High"

    def test_returns_empty_dict_for_missing_file(self, tmp_path):
        result = load_optional_csv(str(tmp_path / "nonexistent.csv"), ["category"])
        assert result == {}

    def test_returns_only_requested_fields(self, tmp_path):
        csv_path = tmp_path / "ai_class.csv"
        write_csv(csv_path, ["domain", "category", "reason", "confidence"], [
            ["evil.com", "Phishing", "Looks bad", "High"],
        ])
        result = load_optional_csv(str(csv_path), ["category", "confidence"])
        assert "category" in result["evil.com"]
        assert "confidence" in result["evil.com"]
        assert "reason" not in result["evil.com"]


# ---------------------------------------------------------------------------
# TestComputeClusters
# ---------------------------------------------------------------------------

class TestComputeClusters:
    """Test infrastructure cluster computation."""

    def _make_domains(self, domain_specs):
        """Build a domains dict from a list of (domain, primary_mx, mx_ip, registrant_org, nameservers) tuples."""
        domains = {}
        for spec in domain_specs:
            d, mx, ip, reg, ns = spec
            domains[d] = {
                "domain": d,
                "primary_mx": mx,
                "mx_ip": ip,
                "registrant_org": reg,
                "nameservers": ns,
            }
        return domains

    def test_shared_mx_cluster(self):
        domains = self._make_domains([
            ("a.com", "mx.shared.com", "1.1.1.1", "OrgA", "ns1.a.com"),
            ("b.com", "mx.shared.com", "2.2.2.2", "OrgB", "ns1.b.com"),
            ("c.com", "mx.shared.com", "3.3.3.3", "OrgC", "ns1.c.com"),
        ])
        result = compute_clusters(domains, min_cluster_size=3)
        # Should have a cluster for shared MX
        mx_nodes = [n for n in result["nodes"] if n["type"] == "mx_host"]
        assert len(mx_nodes) == 1
        assert mx_nodes[0]["label"] == "mx.shared.com"
        # Domain nodes linked to this cluster
        domain_nodes = [n for n in result["nodes"] if n["type"] == "domain"]
        assert len(domain_nodes) >= 3

    def test_shared_ip_cluster(self):
        domains = self._make_domains([
            ("a.com", "mx1.a.com", "10.0.0.1", "OrgA", "ns1.a.com"),
            ("b.com", "mx1.b.com", "10.0.0.1", "OrgB", "ns1.b.com"),
            ("c.com", "mx1.c.com", "10.0.0.1", "OrgC", "ns1.c.com"),
        ])
        result = compute_clusters(domains, min_cluster_size=3)
        ip_nodes = [n for n in result["nodes"] if n["type"] == "ip"]
        assert len(ip_nodes) == 1
        assert ip_nodes[0]["label"] == "10.0.0.1"

    def test_shared_registrar_ns_cluster(self):
        domains = self._make_domains([
            ("a.com", "mx1.a.com", "1.1.1.1", "Evil Corp", "ns1.evil.com;ns2.evil.com"),
            ("b.com", "mx1.b.com", "2.2.2.2", "Evil Corp", "ns1.evil.com;ns2.evil.com"),
            ("c.com", "mx1.c.com", "3.3.3.3", "Evil Corp", "ns1.evil.com;ns2.evil.com"),
        ])
        result = compute_clusters(domains, min_cluster_size=3)
        rns_nodes = [n for n in result["nodes"] if n["type"] == "registrar_ns"]
        assert len(rns_nodes) == 1
        assert "Evil Corp" in rns_nodes[0]["label"]

    def test_min_size_filter(self):
        """Clusters below min_cluster_size should be excluded."""
        domains = self._make_domains([
            ("a.com", "mx.shared.com", "1.1.1.1", "OrgA", "ns1.a.com"),
            ("b.com", "mx.shared.com", "2.2.2.2", "OrgB", "ns1.b.com"),
        ])
        result = compute_clusters(domains, min_cluster_size=3)
        # Only 2 domains share MX, so no clusters meet threshold
        mx_nodes = [n for n in result["nodes"] if n["type"] == "mx_host"]
        assert len(mx_nodes) == 0

    def test_skips_empty_field_values(self):
        """Domains with empty/blank shared fields should not form clusters."""
        domains = self._make_domains([
            ("a.com", "", "1.1.1.1", "OrgA", "ns1.a.com"),
            ("b.com", "", "2.2.2.2", "OrgB", "ns1.b.com"),
            ("c.com", "", "3.3.3.3", "OrgC", "ns1.c.com"),
        ])
        result = compute_clusters(domains, min_cluster_size=3)
        mx_nodes = [n for n in result["nodes"] if n["type"] == "mx_host"]
        assert len(mx_nodes) == 0

    def test_node_schema(self):
        """Verify node schema for infrastructure and domain nodes."""
        domains = self._make_domains([
            ("a.com", "mx.shared.com", "1.1.1.1", "OrgA", "ns1.a.com"),
            ("b.com", "mx.shared.com", "2.2.2.2", "OrgB", "ns1.b.com"),
            ("c.com", "mx.shared.com", "3.3.3.3", "OrgC", "ns1.c.com"),
        ])
        result = compute_clusters(domains, min_cluster_size=3)
        mx_node = [n for n in result["nodes"] if n["type"] == "mx_host"][0]
        assert "id" in mx_node
        assert "type" in mx_node
        assert "label" in mx_node
        assert "size" in mx_node
        # Infrastructure node size = min(5 + domain_count, 30)
        assert mx_node["size"] == min(5 + 3, 30)

        domain_node = [n for n in result["nodes"] if n["type"] == "domain"][0]
        assert domain_node["size"] == 3

    def test_edge_schema(self):
        """Verify edge schema has source and target."""
        domains = self._make_domains([
            ("a.com", "mx.shared.com", "1.1.1.1", "OrgA", "ns1.a.com"),
            ("b.com", "mx.shared.com", "2.2.2.2", "OrgB", "ns1.b.com"),
            ("c.com", "mx.shared.com", "3.3.3.3", "OrgC", "ns1.c.com"),
        ])
        result = compute_clusters(domains, min_cluster_size=3)
        assert len(result["edges"]) >= 3
        for edge in result["edges"]:
            assert "source" in edge
            assert "target" in edge

    def test_output_structure(self):
        """Result must have nodes and edges keys."""
        result = compute_clusters({}, min_cluster_size=3)
        assert "nodes" in result
        assert "edges" in result


# ---------------------------------------------------------------------------
# TestComputeStats
# ---------------------------------------------------------------------------

class TestComputeStats:
    """Test stats computation."""

    def test_basic_stats(self):
        domains = {
            "evil.com": {"domain": "evil.com"},
            "bad.net": {"domain": "bad.net"},
            "test.org": {"domain": "test.org"},
        }
        fp_matches = {
            "evil.com": [{"fp_id": "FP-001", "fp_name": "Test"}],
            "bad.net": [
                {"fp_id": "FP-001", "fp_name": "Test"},
                {"fp_id": "FP-002", "fp_name": "Other"},
            ],
        }
        clusters = {"nodes": [{"type": "mx_host"}, {"type": "domain"}], "edges": []}
        stats = compute_stats(domains, fp_matches, clusters)

        assert stats["total_domains"] == 3
        assert stats["matched_domains"] == 2
        assert stats["unique_fingerprints"] == 2
        assert stats["total_clusters"] >= 0
        assert "last_updated" in stats

    def test_tld_distribution(self):
        domains = {
            "a.com": {"domain": "a.com"},
            "b.com": {"domain": "b.com"},
            "c.net": {"domain": "c.net"},
        }
        stats = compute_stats(domains, {}, {"nodes": [], "edges": []})
        assert "tld_distribution" in stats
        assert stats["tld_distribution"][".com"] == 2
        assert stats["tld_distribution"][".net"] == 1

    def test_top_fingerprints(self):
        domains = {"evil.com": {"domain": "evil.com"}}
        fp_matches = {
            "evil.com": [
                {"fp_id": "FP-001", "fp_name": "Shared Hosting"},
                {"fp_id": "FP-002", "fp_name": "Phishing Kit"},
            ],
        }
        stats = compute_stats(domains, fp_matches, {"nodes": [], "edges": []})
        assert "top_fingerprints" in stats
        assert len(stats["top_fingerprints"]) <= 10

    def test_stats_with_empty_data(self):
        stats = compute_stats({}, {}, {"nodes": [], "edges": []})
        assert stats["total_domains"] == 0
        assert stats["matched_domains"] == 0
        assert stats["unique_fingerprints"] == 0


# ---------------------------------------------------------------------------
# TestBuildOutputs
# ---------------------------------------------------------------------------

class TestBuildOutputs:
    """Test full output generation writing 4 JSON files."""

    def _setup_test_data(self, tmp_path):
        """Create minimal test CSV files and return paths."""
        probed_path = tmp_path / "probed.csv"
        fp_path = tmp_path / "fp.csv"
        output_dir = tmp_path / "output"

        write_csv(probed_path, PROBED_HEADERS, [
            _probed_row(domain="evil.com", asn="16276", primary_mx="mx.evil.com",
                        mx_ip="1.2.3.4", nameservers="ns1.evil.com",
                        registrant_org="Evil Corp"),
            _probed_row(domain="bad.net", asn="99999", primary_mx="mx.evil.com",
                        mx_ip="1.2.3.4", nameservers="ns1.evil.com",
                        registrant_org="Evil Corp"),
            _probed_row(domain="worse.org", asn="11111", primary_mx="mx.evil.com",
                        mx_ip="1.2.3.4", nameservers="ns1.evil.com",
                        registrant_org="Evil Corp"),
        ])
        write_csv(fp_path, FP_HEADERS, [
            ["evil.com", "FP-001", "Test FP", "85", "TP-0001", "asn=16276"],
            ["bad.net", "FP-002", "Other FP", "70", "TP-0002", "cc=FR"],
        ])

        return str(probed_path), str(fp_path), str(output_dir)

    def test_writes_all_four_json_files(self, tmp_path):
        probed_path, fp_path, output_dir = self._setup_test_data(tmp_path)
        build_outputs(
            probed_path=probed_path,
            fingerprints_path=fp_path,
            output_dir=output_dir,
            min_cluster_size=3,
            optional_files={},
        )
        assert os.path.exists(os.path.join(output_dir, "domain_shards.json"))
        assert os.path.exists(os.path.join(output_dir, "fingerprint_matches.json"))
        assert os.path.exists(os.path.join(output_dir, "clusters.json"))
        assert os.path.exists(os.path.join(output_dir, "stats.json"))
        assert os.path.exists(os.path.join(output_dir, "infra_index.json"))

    def test_domains_json_structure(self, tmp_path):
        probed_path, fp_path, output_dir = self._setup_test_data(tmp_path)
        build_outputs(
            probed_path=probed_path,
            fingerprints_path=fp_path,
            output_dir=output_dir,
            min_cluster_size=3,
            optional_files={},
        )
        # Load from shard files (evil.com starts with 'e', bad.net with 'b')
        with open(os.path.join(output_dir, "domains_e.json"), "r") as f:
            e_data = json.load(f)
        with open(os.path.join(output_dir, "domains_b.json"), "r") as f:
            b_data = json.load(f)
        assert "evil.com" in e_data
        assert "bad.net" in b_data
        assert "matches" in e_data["evil.com"]
        assert len(e_data["evil.com"]["matches"]) == 1
        assert e_data["evil.com"]["matches"][0]["fp_id"] == "FP-001"

    def test_fingerprint_matches_json_structure(self, tmp_path):
        probed_path, fp_path, output_dir = self._setup_test_data(tmp_path)
        build_outputs(
            probed_path=probed_path,
            fingerprints_path=fp_path,
            output_dir=output_dir,
            min_cluster_size=3,
            optional_files={},
        )
        with open(os.path.join(output_dir, "fingerprint_matches.json"), "r") as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) == 2
        # Verify enrichment from probed data
        evil_match = [m for m in data if m["domain"] == "evil.com"][0]
        assert "tld" in evil_match
        assert "registrar" in evil_match

    def test_clusters_json_structure(self, tmp_path):
        probed_path, fp_path, output_dir = self._setup_test_data(tmp_path)
        build_outputs(
            probed_path=probed_path,
            fingerprints_path=fp_path,
            output_dir=output_dir,
            min_cluster_size=3,
            optional_files={},
        )
        with open(os.path.join(output_dir, "clusters.json"), "r") as f:
            data = json.load(f)
        assert "nodes" in data
        assert "edges" in data

    def test_stats_json_structure(self, tmp_path):
        probed_path, fp_path, output_dir = self._setup_test_data(tmp_path)
        build_outputs(
            probed_path=probed_path,
            fingerprints_path=fp_path,
            output_dir=output_dir,
            min_cluster_size=3,
            optional_files={},
        )
        with open(os.path.join(output_dir, "stats.json"), "r") as f:
            data = json.load(f)
        assert data["total_domains"] == 3
        assert data["matched_domains"] == 2
        assert "last_updated" in data
        assert "tld_distribution" in data
        assert "top_fingerprints" in data

    def test_optional_data_merged_into_domains(self, tmp_path):
        probed_path, fp_path, output_dir = self._setup_test_data(tmp_path)

        # Create optional ai_classifications CSV
        ai_class_path = tmp_path / "ai_class.csv"
        write_csv(ai_class_path, ["domain", "category", "reason", "confidence"], [
            ["evil.com", "Phishing", "Looks bad", "High"],
        ])

        build_outputs(
            probed_path=probed_path,
            fingerprints_path=fp_path,
            output_dir=output_dir,
            min_cluster_size=3,
            optional_files={
                "ai_classifications": {
                    "path": str(ai_class_path),
                    "fields": ["category", "confidence"],
                    "prefix": "ai_",
                },
            },
        )
        # Load from shard files
        with open(os.path.join(output_dir, "domains_e.json"), "r") as f:
            e_data = json.load(f)
        with open(os.path.join(output_dir, "domains_b.json"), "r") as f:
            b_data = json.load(f)
        assert e_data["evil.com"]["ai_category"] == "Phishing"
        assert e_data["evil.com"]["ai_confidence"] == "High"
        # Domain without AI classification should not have these keys
        assert "ai_category" not in b_data["bad.net"]


# ---------------------------------------------------------------------------
# TestComputeRiskScore
# ---------------------------------------------------------------------------

class TestComputeRiskScore:
    """Test composite risk score computation."""

    def test_all_zeros(self):
        """Domain with no risk signals should score 0."""
        score, level, signals = compute_risk_score({})
        assert score == 0
        assert level == "Low"

    def test_high_fingerprint_confidence(self):
        """High FP confidence alone should contribute 25% of max."""
        data = {"matches": [{"confidence": "100"}]}
        score, level, signals = compute_risk_score(data)
        assert signals["fingerprint"] == 100.0
        assert score == 25  # 100 * 0.25

    def test_critical_score(self):
        """Multiple high signals should produce Critical level."""
        data = {
            "matches": [{"confidence": "95"}],
            "vt_malicious_count": "15",
            "os_match_score": "90",
            "rbl_hits": "4",
            "phishtank_match": "True",
            "typosquat_target": "google.com",
            "age_days": "5",
        }
        score, level, signals = compute_risk_score(data)
        assert score >= 75
        assert level == "Critical"

    def test_medium_score(self):
        """Moderate signals should produce Medium level."""
        data = {
            "matches": [{"confidence": "50"}],
            "vt_malicious_count": "2",
        }
        score, level, signals = compute_risk_score(data)
        assert 10 <= score <= 50

    def test_safe_float_edge_cases(self):
        assert _safe_float(None) == 0.0
        assert _safe_float("") == 0.0
        assert _safe_float("abc") == 0.0
        assert _safe_float("42.5") == 42.5
        assert _safe_float(10) == 10.0

    def test_score_capped_at_100(self):
        """Score should never exceed 100."""
        data = {
            "matches": [{"confidence": "200"}],
            "vt_malicious_count": "100",
            "os_match_score": "200",
            "rbl_hits": "50",
            "phishtank_match": "True",
            "typosquat_target": "x.com",
            "age_days": "1",
        }
        score, level, signals = compute_risk_score(data)
        assert score <= 100


# ---------------------------------------------------------------------------
# TestBuildInfraIndex
# ---------------------------------------------------------------------------

class TestBuildInfraIndex:
    """Test infrastructure pivot index generation."""

    def test_asn_index(self):
        """Domains sharing an ASN should be grouped."""
        domains = {
            "a.com": {"asn": "16276", "primary_mx": "", "registrant_org": ""},
            "b.com": {"asn": "16276", "primary_mx": "", "registrant_org": ""},
            "c.com": {"asn": "99999", "primary_mx": "", "registrant_org": ""},
        }
        index = build_infra_index(domains, {})
        assert "16276" in index["asn"]
        assert len(index["asn"]["16276"]) == 2
        # Single-domain ASN should not appear
        assert "99999" not in index["asn"]

    def test_mx_index(self):
        domains = {
            "a.com": {"asn": "", "primary_mx": "mx.shared.com", "registrant_org": ""},
            "b.com": {"asn": "", "primary_mx": "mx.shared.com", "registrant_org": ""},
        }
        index = build_infra_index(domains, {})
        assert "mx.shared.com" in index["mx"]
        assert len(index["mx"]["mx.shared.com"]) == 2

    def test_fp_index(self):
        fp_matches = {
            "a.com": [{"fp_id": "FP-001"}],
            "b.com": [{"fp_id": "FP-001"}],
            "c.com": [{"fp_id": "FP-002"}],
        }
        index = build_infra_index({}, fp_matches)
        assert "FP-001" in index["fp"]
        assert len(index["fp"]["FP-001"]) == 2
        # Single-domain FP should not appear
        assert "FP-002" not in index["fp"]

    def test_empty_inputs(self):
        index = build_infra_index({}, {})
        assert index == {"asn": {}, "mx": {}, "registrar": {}, "fp": {}, "a_record": {}}

    def test_deduplication(self):
        """Domains should be deduplicated in index entries."""
        fp_matches = {
            "a.com": [{"fp_id": "FP-001"}, {"fp_id": "FP-001"}],
            "b.com": [{"fp_id": "FP-001"}],
        }
        index = build_infra_index({}, fp_matches)
        assert len(index["fp"]["FP-001"]) == 2  # a.com appears only once
