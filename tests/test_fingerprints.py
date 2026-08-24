#!/usr/bin/env python3
"""Tests for match_fingerprints.py — infrastructure fingerprint matching engine."""

import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from match_fingerprints import (
    validate_fingerprint,
    resolve_field,
    check_indicator,
    evaluate_fingerprint,
    calculate_confidence,
    load_fingerprints_from_list,
    match_domain,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fp(**overrides):
    """Return a minimal valid fingerprint dict."""
    fp = {
        "id": "FP-TEST",
        "name": "Test Fingerprint",
        "description": "Unit test",
        "version": 1,
        "indicators": [
            {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
        ],
        "confidence_base": 70,
        "confidence_modifiers": [],
        "flame_tp_ids": ["TP-0001"],
        "ttl_days": 30,
    }
    fp.update(overrides)
    return fp


def _make_row(**overrides):
    """Return a minimal domain CSV row dict with empty-string defaults."""
    row = {
        "domain": "",
        "asn": "",
        "nameservers": "",
        "primary_mx": "",
        "registry": "",
        "cc": "",
        "http_title": "",
        "https_title": "",
        "risk_tags": "",
        "http_status": "",
        "mx_records": "",
    }
    row.update(overrides)
    return row


# ---------------------------------------------------------------------------
# TestSchemaValidation
# ---------------------------------------------------------------------------

class TestSchemaValidation:
    """Validate fingerprint schema checking."""

    def test_valid_fingerprint_loads(self):
        fp = _make_fp()
        result = validate_fingerprint(fp, source="test")
        assert result["id"] == "FP-TEST"

    def test_missing_required_key_raises(self):
        fp = _make_fp()
        del fp["id"]
        with pytest.raises(ValueError, match="id"):
            validate_fingerprint(fp, source="test")

    def test_unknown_match_type_raises(self):
        fp = _make_fp(indicators=[
            {"field": "asn", "match_type": "fuzzy", "value": "16276", "required": True},
        ])
        with pytest.raises(ValueError, match="match_type"):
            validate_fingerprint(fp, source="test")

    def test_invalid_regex_raises(self):
        fp = _make_fp(indicators=[
            {"field": "http_title", "match_type": "regex", "value": "[invalid(", "required": True},
        ])
        with pytest.raises(ValueError, match="regex"):
            validate_fingerprint(fp, source="test")

    def test_regex_exceeding_max_length_raises(self):
        fp = _make_fp(indicators=[
            {"field": "http_title", "match_type": "regex", "value": "a" * 201, "required": True},
        ])
        with pytest.raises(ValueError, match="exceeding"):
            validate_fingerprint(fp, source="test")


# ---------------------------------------------------------------------------
# TestFieldAlias
# ---------------------------------------------------------------------------

class TestFieldAlias:
    """Validate field alias resolution."""

    def test_alias_ns_resolves_to_nameservers(self):
        assert resolve_field("ns") == "nameservers"

    def test_direct_column_name_passes_through(self):
        assert resolve_field("asn") == "asn"


# ---------------------------------------------------------------------------
# TestMatchTypes
# ---------------------------------------------------------------------------

class TestMatchTypes:
    """Validate individual match-type logic in check_indicator."""

    def test_exact_match(self):
        assert check_indicator("16276", "exact", "16276") is True

    def test_exact_match_case_insensitive(self):
        assert check_indicator("GoDaddy", "exact", "godaddy") is True

    def test_contains_match_in_semicolon_field(self):
        assert check_indicator(
            "ns1.cprapid.com;ns2.cprapid.com", "contains", "cprapid.com"
        ) is True

    def test_regex_match(self):
        assert check_indicator(
            "crypto-wallet-login.com", "regex", r"crypto.*login"
        ) is True

    def test_range_match_numeric(self):
        assert check_indicator("45102", "range", "45100-45110") is True

    def test_range_no_match_outside_bounds(self):
        assert check_indicator("99999", "range", "45100-45110") is False

    def test_contains_no_match(self):
        assert check_indicator(
            "ns1.cloudflare.com", "contains", "cprapid.com"
        ) is False


# ---------------------------------------------------------------------------
# TestScoring
# ---------------------------------------------------------------------------

class TestScoring:
    """Validate confidence calculation with modifiers and clamping."""

    def test_base_confidence_no_modifiers(self):
        fp = _make_fp(confidence_base=70, confidence_modifiers=[])
        row = _make_row()
        assert calculate_confidence(fp, row) == 70

    def test_positive_delta_applied(self):
        fp = _make_fp(
            confidence_base=70,
            confidence_modifiers=[
                {"field": "cc", "match_type": "exact", "value": "FR", "delta": 10},
            ],
        )
        row = _make_row(cc="FR")
        assert calculate_confidence(fp, row) == 80

    def test_negative_delta_applied(self):
        fp = _make_fp(
            confidence_base=70,
            confidence_modifiers=[
                {"field": "cc", "match_type": "exact", "value": "US", "delta": -20},
            ],
        )
        row = _make_row(cc="US")
        assert calculate_confidence(fp, row) == 50

    def test_confidence_clamped_to_100(self):
        fp = _make_fp(
            confidence_base=95,
            confidence_modifiers=[
                {"field": "cc", "match_type": "exact", "value": "FR", "delta": 10},
                {"field": "asn", "match_type": "exact", "value": "16276", "delta": 15},
            ],
        )
        row = _make_row(cc="FR", asn="16276")
        assert calculate_confidence(fp, row) == 100

    def test_confidence_clamped_to_zero(self):
        fp = _make_fp(
            confidence_base=10,
            confidence_modifiers=[
                {"field": "cc", "match_type": "exact", "value": "US", "delta": -30},
            ],
        )
        row = _make_row(cc="US")
        assert calculate_confidence(fp, row) == 0


# ---------------------------------------------------------------------------
# TestEvaluateFingerprint
# ---------------------------------------------------------------------------

class TestEvaluateFingerprint:
    """Validate full fingerprint evaluation against a domain row."""

    def test_all_required_pass_returns_match(self):
        fp = _make_fp(indicators=[
            {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
            {"field": "nameservers", "match_type": "contains", "value": "cprapid.com", "required": True},
        ])
        fp = validate_fingerprint(fp, source="test")
        row = _make_row(asn="16276", nameservers="ns1.cprapid.com;ns2.cprapid.com")
        result = evaluate_fingerprint(fp, row)
        assert result is not None
        assert result["fp_id"] == "FP-TEST"
        # Verify evidence format: exact uses "=", contains uses "~"
        assert "asn=16276" in result["evidence"]
        assert "nameservers~cprapid.com" in result["evidence"]

    def test_required_indicator_fails_returns_none(self):
        fp = _make_fp(indicators=[
            {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
        ])
        fp = validate_fingerprint(fp, source="test")
        row = _make_row(asn="99999")
        assert evaluate_fingerprint(fp, row) is None

    def test_non_required_failure_still_matches(self):
        fp = _make_fp(indicators=[
            {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
            {"field": "primary_mx", "match_type": "contains", "value": "cprapid.com", "required": False},
        ])
        fp = validate_fingerprint(fp, source="test")
        row = _make_row(asn="16276", primary_mx="other.com")
        result = evaluate_fingerprint(fp, row)
        assert result is not None
        assert result["fp_id"] == "FP-TEST"

    def test_empty_field_treated_as_no_match(self):
        fp = _make_fp(indicators=[
            {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
        ])
        fp = validate_fingerprint(fp, source="test")
        row = _make_row(asn="")
        assert evaluate_fingerprint(fp, row) is None

    def test_missing_field_treated_as_no_match(self):
        fp = _make_fp(indicators=[
            {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
        ])
        fp = validate_fingerprint(fp, source="test")
        row = _make_row()
        del row["asn"]
        assert evaluate_fingerprint(fp, row) is None


# ---------------------------------------------------------------------------
# TestMatchDomain
# ---------------------------------------------------------------------------

class TestMatchDomain:
    """Validate matching a single domain row against multiple fingerprints."""

    def test_domain_matches_multiple_fingerprints(self):
        fp1 = _make_fp(
            id="FP-001",
            name="FP One",
            indicators=[
                {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
            ],
        )
        fp2 = _make_fp(
            id="FP-002",
            name="FP Two",
            indicators=[
                {"field": "nameservers", "match_type": "contains", "value": "cprapid.com", "required": True},
            ],
        )
        fps = load_fingerprints_from_list([fp1, fp2])
        row = _make_row(asn="16276", nameservers="ns1.cprapid.com;ns2.cprapid.com")
        matches = match_domain(row, fps)
        assert len(matches) == 2

    def test_domain_matches_zero_fingerprints(self):
        fp1 = _make_fp(
            id="FP-001",
            indicators=[
                {"field": "asn", "match_type": "exact", "value": "16276", "required": True},
            ],
        )
        fps = load_fingerprints_from_list([fp1])
        row = _make_row(asn="99999")
        matches = match_domain(row, fps)
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# TestFP0007Typosquat
# ---------------------------------------------------------------------------

class TestFP0007Typosquat:
    """Validate the rewritten FP-0007 fires correctly with dnstwist data."""

    def test_fires_on_dnstwist_match(self):
        """FP-0007 should fire when dnstwist_match is True with full evidence."""
        fp = _make_fp(
            id="FP-0007",
            name="Typosquat Evasion Infrastructure",
            indicators=[
                {"field": "dnstwist_match", "match_type": "exact", "value": "True", "required": True},
            ],
            confidence_base=45,
            confidence_modifiers=[
                {"field": "redirects_to_brand", "match_type": "exact", "value": "True", "delta": 30},
                {"field": "primary_mx", "match_type": "contains", "value": ".", "delta": 20},
                {"field": "registrant_mismatch", "match_type": "exact", "value": "True", "delta": 15},
            ],
            flame_tp_ids=["TP-0012"],
        )
        fp = validate_fingerprint(fp, source="test")
        row = _make_row(
            domain="amaz0n.com",
            dnstwist_match="True",
            redirects_to_brand="True",
            primary_mx="mx.evilhost.com",
            registrant_mismatch="True",
        )
        result = evaluate_fingerprint(fp, row)
        assert result is not None
        assert result["fp_id"] == "FP-0007"
        assert result["confidence"] == 100  # 45 + 30 + 20 + 15 = 110, clamped to 100

    def test_does_not_fire_without_dnstwist_match(self):
        """FP-0007 should NOT fire when dnstwist_match is False."""
        fp = _make_fp(
            id="FP-0007",
            indicators=[
                {"field": "dnstwist_match", "match_type": "exact", "value": "True", "required": True},
            ],
            confidence_base=45,
        )
        fp = validate_fingerprint(fp, source="test")
        row = _make_row(dnstwist_match="False")
        assert evaluate_fingerprint(fp, row) is None

    def test_base_score_with_no_modifiers_matching(self):
        """With only dnstwist_match, score should be base 45."""
        fp = _make_fp(
            id="FP-0007",
            indicators=[
                {"field": "dnstwist_match", "match_type": "exact", "value": "True", "required": True},
            ],
            confidence_base=45,
            confidence_modifiers=[
                {"field": "redirects_to_brand", "match_type": "exact", "value": "True", "delta": 30},
            ],
        )
        fp = validate_fingerprint(fp, source="test")
        row = _make_row(dnstwist_match="True", redirects_to_brand="False")
        result = evaluate_fingerprint(fp, row)
        assert result is not None
        assert result["confidence"] == 45

    def test_yaml_loads_successfully(self):
        """The actual FP-0007 YAML file should load and validate."""
        import yaml
        yaml_path = os.path.join(
            os.path.dirname(__file__), '..', 'config', 'fingerprints',
            'FP-0007-typosquat-evasion-infra.yaml'
        )
        with open(yaml_path, 'r') as f:
            fp = yaml.safe_load(f)
        result = validate_fingerprint(fp, source=yaml_path)
        assert result["id"] == "FP-0007"
        assert result["confidence_base"] == 45
        # Verify the required gate
        required_indicators = [i for i in result["indicators"] if i.get("required")]
        assert len(required_indicators) == 1
        assert required_indicators[0]["field"] == "dnstwist_match"


# === any_of groups and the zero-required guard ===

class TestAnyOfSemantics:
    """The engine only had AND (`required: true`) semantics. Authors needing
    "match any one of these" set every indicator to required: false -- which
    made all_required_pass vacuously true, so the fingerprint matched EVERY
    row. Four fingerprints did this (FP-0008, FP-0009, FP-0010, FP-0011),
    producing 990,945 junk match rows and pushing fingerprint_matches.csv past
    GitHub's 100 MB file limit, which broke the daily push.
    """

    def _fp(self, **kw):
        base = {
            "id": "FP-TEST", "name": "test", "description": "d", "version": 1,
            "indicators": [], "confidence_base": 50,
        }
        base.update(kw)
        return base

    def test_any_of_matches_when_one_matches(self):
        fp = validate_fingerprint(self._fp(
            indicators=[{"field": "primary_mx", "match_type": "contains",
                         "value": "anchor.example", "required": True}],
            any_of=[{"field": "domain", "match_type": "contains", "value": "aaa"},
                    {"field": "domain", "match_type": "contains", "value": "bbb"}],
        ))
        assert evaluate_fingerprint(fp, {"domain": "x-bbb-y", "primary_mx": "anchor.example"})

    def test_any_of_rejects_when_none_match(self):
        fp = validate_fingerprint(self._fp(
            indicators=[{"field": "primary_mx", "match_type": "contains",
                         "value": "anchor.example", "required": True}],
            any_of=[{"field": "domain", "match_type": "contains", "value": "aaa"},
                    {"field": "domain", "match_type": "contains", "value": "bbb"}],
        ))
        assert evaluate_fingerprint(fp, {"domain": "nothing", "primary_mx": "anchor.example"}) is None

    def test_any_of_alone_is_sufficient_gating(self):
        """A fingerprint may be entirely any_of -- that is still a real gate."""
        fp = validate_fingerprint(self._fp(
            indicators=[],
            any_of=[{"field": "domain", "match_type": "contains", "value": "aaa"}],
        ))
        assert evaluate_fingerprint(fp, {"domain": "zzz-aaa"})
        assert evaluate_fingerprint(fp, {"domain": "unrelated"}) is None

    def test_required_and_any_of_are_anded_together(self):
        fp = validate_fingerprint(self._fp(
            indicators=[{"field": "asn", "match_type": "exact",
                         "value": "16276", "required": True}],
            any_of=[{"field": "domain", "match_type": "contains", "value": "aaa"}],
        ))
        assert evaluate_fingerprint(fp, {"asn": "16276", "domain": "aaa"})
        assert evaluate_fingerprint(fp, {"asn": "99999", "domain": "aaa"}) is None
        assert evaluate_fingerprint(fp, {"asn": "16276", "domain": "no"}) is None


class TestNoUngatedFingerprints:
    """A fingerprint that can match every row is never intentional."""

    def test_zero_required_and_zero_any_of_is_rejected(self):
        with pytest.raises(ValueError, match="(?i)required|any_of|gate"):
            validate_fingerprint({
                "id": "FP-BAD", "name": "n", "description": "d", "version": 1,
                "confidence_base": 50,
                "indicators": [{"field": "domain", "match_type": "contains",
                                "value": "x", "required": False}],
            })

    def test_every_shipped_fingerprint_is_gated(self):
        """Regression guard: no fingerprint in config/ may match every row."""
        import glob, os, yaml, io
        here = os.path.dirname(__file__)
        ungated = []
        for p in sorted(glob.glob(os.path.join(here, "..", "config", "fingerprints", "*.yaml"))):
            d = yaml.safe_load(io.open(p, encoding="utf-8"))
            req = [i for i in (d.get("indicators") or []) if i.get("required", True)]
            if not req and not d.get("any_of"):
                ungated.append(d.get("id", os.path.basename(p)))
        assert not ungated, f"these match every row: {ungated}"
