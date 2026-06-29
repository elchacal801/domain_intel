#!/usr/bin/env python3
"""
test_export_stix.py

Tests for the STIX 2.1 export pipeline including:
- Bundle schema validation
- Indicator generation from CSV data
- FLAME attack-pattern integration
- Relationship generation
- Deduplication
- Graceful degradation without FLAME
"""

import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from unittest import mock

import pytest
import stix2

# Add scripts to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from export_stix import (
    build_identity,
    build_indicator,
    build_relationship,
    det_id,
    extract_flame_attack_patterns,
    write_bundle,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_flame_bundle():
    """Minimal FLAME STIX bundle for testing."""
    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "identity",
                "id": "identity--flame-test",
                "spec_version": "2.1",
                "name": "FLAME Project",
                "identity_class": "organization",
                "created": "2026-01-01T00:00:00Z",
                "modified": "2026-01-01T00:00:00Z",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--test-tp-0001",
                "spec_version": "2.1",
                "name": "Treasury Mgmt ATO",
                "created": "2026-01-01T00:00:00Z",
                "modified": "2026-01-01T00:00:00Z",
                "external_references": [
                    {
                        "source_name": "FLAME Project",
                        "description": "Threat Path TP-0001",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--test-tp-0002",
                "spec_version": "2.1",
                "name": "BEC Wire Fraud",
                "created": "2026-01-01T00:00:00Z",
                "modified": "2026-01-01T00:00:00Z",
                "external_references": [
                    {
                        "source_name": "FLAME Project",
                        "description": "Threat Path TP-0002",
                    }
                ],
            },
        ],
    }


@pytest.fixture
def tmp_output(tmp_path):
    """Temporary output path."""
    return str(tmp_path / "test_bundle.json")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDeterministicIds:
    """Test deterministic UUID generation."""

    def test_same_seed_same_id(self):
        id1 = det_id("indicator", "test-seed")
        id2 = det_id("indicator", "test-seed")
        assert id1 == id2

    def test_different_seed_different_id(self):
        id1 = det_id("indicator", "seed-a")
        id2 = det_id("indicator", "seed-b")
        assert id1 != id2

    def test_id_format(self):
        result = det_id("indicator", "test")
        assert result.startswith("indicator--")
        # Validate UUID portion
        uuid_part = result.split("--")[1]
        uuid.UUID(uuid_part)  # Should not raise


class TestBuildIdentity:
    """Test identity object construction."""

    def test_identity_valid(self):
        identity = build_identity()
        assert identity.type == "identity"
        assert identity.name == "Domain Intel Bot"
        assert identity.identity_class == "system"
        # Validate it serializes without error
        json.loads(identity.serialize())

    def test_identity_has_marking(self):
        identity = build_identity()
        assert len(identity.object_marking_refs) == 1


class TestBuildIndicator:
    """Test indicator construction."""

    def test_domain_indicator(self):
        ind = build_indicator(
            "evil.example.com", "domain-name",
            ["malicious-activity"], "Test Domain"
        )
        assert ind is not None
        assert ind.type == "indicator"
        assert "evil.example.com" in ind.pattern
        assert ind.pattern_type == "stix"

    def test_asn_indicator(self):
        ind = build_indicator(
            "AS12345", "autonomous-system",
            ["hosting-provider"], "Test ASN"
        )
        assert ind is not None
        assert "12345" in ind.pattern

    def test_ip_indicator(self):
        ind = build_indicator(
            "192.0.2.1", "ipv4-addr",
            ["tor-exit"], "Test IP"
        )
        assert ind is not None
        assert "192.0.2.1" in ind.pattern

    def test_invalid_asn_returns_none(self):
        ind = build_indicator(
            "NOT-AN-ASN", "autonomous-system",
            ["test"], "Bad ASN"
        )
        assert ind is None

    def test_unknown_type_returns_none(self):
        ind = build_indicator(
            "test", "unknown-type",
            ["test"], "Unknown"
        )
        assert ind is None

    def test_deterministic_domain_ids(self):
        ind1 = build_indicator("evil.com", "domain-name", ["test"], "T")
        ind2 = build_indicator("evil.com", "domain-name", ["test"], "T")
        assert ind1.id == ind2.id


class TestBuildRelationship:
    """Test relationship construction."""

    def test_relationship_valid(self):
        src = det_id("indicator", "test-src")
        tgt = det_id("attack-pattern", "test-tgt")
        rel = build_relationship(src, tgt)
        assert rel.type == "relationship"
        assert rel.relationship_type == "indicates"
        assert rel.source_ref == src
        assert rel.target_ref == tgt

    def test_deterministic_relationship_ids(self):
        src = det_id("indicator", "test-src")
        tgt = det_id("attack-pattern", "test-tgt")
        rel1 = build_relationship(src, tgt)
        rel2 = build_relationship(src, tgt)
        assert rel1.id == rel2.id


class TestExtractFlameAttackPatterns:
    """Test FLAME bundle attack-pattern extraction."""

    def test_extracts_attack_patterns(self, sample_flame_bundle):
        aps = extract_flame_attack_patterns(sample_flame_bundle)
        assert "TP-0001" in aps
        assert "TP-0002" in aps
        assert aps["TP-0001"]["name"] == "Treasury Mgmt ATO"

    def test_ignores_non_attack_patterns(self, sample_flame_bundle):
        aps = extract_flame_attack_patterns(sample_flame_bundle)
        # Identity should not be extracted
        assert len(aps) == 2

    def test_empty_bundle(self):
        aps = extract_flame_attack_patterns({"objects": []})
        assert len(aps) == 0

    def test_missing_objects_key(self):
        aps = extract_flame_attack_patterns({})
        assert len(aps) == 0


class TestWriteBundle:
    """Test bundle writing and validation."""

    def test_write_valid_bundle(self, tmp_output):
        identity = build_identity()
        ind = build_indicator(
            "test.example.com", "domain-name",
            ["test"], "Test"
        )
        write_bundle([identity, ind], tmp_output, "test")

        # Verify file exists and is valid JSON
        assert os.path.exists(tmp_output)
        with open(tmp_output, "r") as f:
            data = json.load(f)
        assert data["type"] == "bundle"
        assert len(data["objects"]) == 2

    def test_bundle_validates_stix(self, tmp_output):
        identity = build_identity()
        write_bundle([identity], tmp_output, "test")

        with open(tmp_output, "r") as f:
            raw = f.read()
        # Should not raise
        stix2.parse(raw, allow_custom=True)


class TestGracefulDegradation:
    """Test that export works without FLAME."""

    def test_no_flame_bundle(self):
        """extract_flame_attack_patterns handles None gracefully."""
        # Should return empty dict when no FLAME data
        result = extract_flame_attack_patterns({"objects": []})
        assert result == {}

    def test_no_classification_file(self):
        """load_flame_tp_mapping handles missing file."""
        from export_stix import load_flame_tp_mapping
        with mock.patch("export_stix.CLASSIFICATION_FILE", "/nonexistent"):
            result = load_flame_tp_mapping()
            assert result == {}
