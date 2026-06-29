#!/usr/bin/env python3
"""
test_sync_detection_rules.py

Tests for the FLAME detection rule sync pipeline:
- FLAME rules fetch (mocked)
- Sigma-to-triage conversion
- SQL-to-triage conversion
- Rule YAML format validation
"""

import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from sync_detection_rules import (
    convert_rules,
    extract_sigma_patterns,
    extract_sql_patterns,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_sigma_rule():
    """Sigma rule with domain_intel-relevant patterns."""
    return {
        "tp_id": "TP-0001",
        "type": "sigma",
        "title": "Test Sigma Rule",
        "content": (
            "title: Suspicious Nameserver\n"
            "logsource:\n"
            "    product: dns\n"
            "detection:\n"
            "    selection:\n"
            "        nameserver_value: 'evil-ns.example.com'\n"
            "    condition: selection\n"
        ),
    }


@pytest.fixture
def sample_sql_rule():
    """SQL rule with MX patterns."""
    return {
        "tp_id": "TP-0003",
        "type": "sql",
        "title": "Test SQL Rule",
        "content": (
            "SELECT * FROM domains\n"
            "WHERE primary_mx LIKE '%suspicious-mx.com%'\n"
            "AND nameservers LIKE '%bad-ns.net%'\n"
        ),
    }


@pytest.fixture
def sample_rules():
    """Collection of sample rules."""
    return [
        {
            "tp_id": "TP-0001",
            "type": "sigma",
            "title": "NS Pattern",
            "content": (
                "logsource:\n"
                "    product: dns\n"
                "detection:\n"
                "    selection:\n"
                "        nameserver_value: 'evil.ns.com'\n"
            ),
        },
        {
            "tp_id": "TP-0003",
            "type": "sql",
            "title": "MX Pattern",
            "content": "SELECT * FROM d WHERE primary_mx LIKE '%badmx.com%'",
        },
        {
            "tp_id": "TP-0005",
            "type": "spl",
            "title": "SPL Rule without patterns",
            "content": "index=main sourcetype=access_log",
        },
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestExtractSigmaPatterns:
    """Test Sigma rule pattern extraction."""

    def test_extracts_nameserver_pattern(self, sample_sigma_rule):
        patterns = extract_sigma_patterns(sample_sigma_rule)
        ns_patterns = [p for p in patterns if p["field"] == "nameservers"]
        assert len(ns_patterns) >= 1

    def test_extracts_cidr_patterns(self):
        rule = {
            "content": "source_ip|cidr: '203.0.113.0/24'"
        }
        patterns = extract_sigma_patterns(rule)
        cidr_patterns = [p for p in patterns if p["field"] == "mx_ip"]
        assert len(cidr_patterns) >= 1
        assert cidr_patterns[0]["operator"] == "cidr"

    def test_ignores_private_cidrs(self):
        rule = {
            "content": "source_ip|cidr: '10.0.0.0/8'"
        }
        patterns = extract_sigma_patterns(rule)
        cidr_patterns = [p for p in patterns if p["field"] == "mx_ip"]
        assert len(cidr_patterns) == 0

    def test_empty_content(self):
        patterns = extract_sigma_patterns({"content": ""})
        assert patterns == []


class TestExtractSqlPatterns:
    """Test SQL pattern extraction."""

    def test_extracts_mx_pattern(self, sample_sql_rule):
        patterns = extract_sql_patterns(sample_sql_rule)
        mx_patterns = [p for p in patterns if p["field"] == "primary_mx"]
        assert len(mx_patterns) >= 1
        assert "suspicious-mx.com" in mx_patterns[0]["value"]

    def test_extracts_ns_pattern(self, sample_sql_rule):
        patterns = extract_sql_patterns(sample_sql_rule)
        ns_patterns = [p for p in patterns if p["field"] == "nameservers"]
        assert len(ns_patterns) >= 1

    def test_empty_content(self):
        patterns = extract_sql_patterns({"content": ""})
        assert patterns == []


class TestConvertRules:
    """Test full rule conversion pipeline."""

    def test_converts_rules_with_patterns(self, sample_rules):
        result = convert_rules(sample_rules)
        # Only rules with extractable patterns should be included
        for r in result:
            assert len(r["patterns"]) > 0
            assert r["enabled"] is False
            assert r["rule_id"].startswith("FLAME-")
            assert "source_tp" in r

    def test_rules_disabled_by_default(self, sample_rules):
        result = convert_rules(sample_rules)
        for r in result:
            assert r["enabled"] is False

    def test_rule_id_format(self, sample_rules):
        result = convert_rules(sample_rules)
        for r in result:
            assert r["rule_id"].startswith("FLAME-TP-")

    def test_empty_rules(self):
        result = convert_rules([])
        assert result == []

    def test_rules_without_patterns_excluded(self):
        rules = [
            {
                "tp_id": "TP-0099",
                "type": "pseudocode",
                "title": "No patterns here",
                "content": "If suspicious activity detected, alert analyst",
            }
        ]
        result = convert_rules(rules)
        assert len(result) == 0


class TestOutputFormat:
    """Test the output YAML format."""

    def test_valid_yaml_output(self, sample_rules, tmp_path):
        """Verify the output is valid YAML with expected structure."""
        result = convert_rules(sample_rules)
        output = {
            "version": "1.0",
            "source": "FLAME Project (auto-synced)",
            "rules": result,
        }
        output_path = tmp_path / "test_rules.yaml"
        with open(output_path, "w") as f:
            yaml.dump(output, f, default_flow_style=False)

        # Verify it loads back correctly
        with open(output_path, "r") as f:
            loaded = yaml.safe_load(f)

        assert loaded["version"] == "1.0"
        assert isinstance(loaded["rules"], list)
        for r in loaded["rules"]:
            assert "rule_id" in r
            assert "patterns" in r
            assert isinstance(r["patterns"], list)
