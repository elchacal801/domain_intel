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
