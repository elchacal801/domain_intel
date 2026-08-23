#!/usr/bin/env python3
"""Tests for the algorithmic typosquat pre-scoring in ai_typosquat.py."""

import os
import sys

import pytest

# Allow importing from scripts/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

# Patch heavy imports before loading the module (no API key needed for tests)
from unittest.mock import MagicMock

# Stub heavy/optional imports ONLY while importing the script under test.
# These modules have import-time side effects (LLMClient instantiation,
# load_dotenv) that need no API keys here. The previous sys.modules state is
# restored immediately afterwards -- leaving the stubs in place leaks them into
# every later test module, which is what caused 66 spurious failures when the
# suite ran in alphabetical order.
_stubbed = ("shared.llm_client", "dotenv")
_saved = {n: sys.modules.get(n) for n in _stubbed}
for _n in _stubbed:
    sys.modules.setdefault(_n, MagicMock())

try:
    from ai_typosquat import (  # noqa: E402
        score_typosquat,
        _strip_domain,
        _levenshtein,
        _apply_homoglyphs,
    )
finally:
    for _n, _prev in _saved.items():
        if _prev is None:
            sys.modules.pop(_n, None)
        else:
            sys.modules[_n] = _prev

# Default target list used for most tests
TARGETS = ["Google", "Microsoft", "PayPal", "Chase", "Netflix", "Apple"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = {"domain", "target", "reason", "confidence"}


def _assert_match(result, expected_target=None, confidence="High"):
    """Assert that a result is a valid typosquat match dict."""
    assert result is not None, "Expected a match but got None"
    assert set(result.keys()) == REQUIRED_FIELDS
    assert result["confidence"] == confidence
    if expected_target:
        assert result["target"] == expected_target
    assert len(result["reason"]) > 5


# ---------------------------------------------------------------------------
# _strip_domain — TLD stripping
# ---------------------------------------------------------------------------

class TestStripDomain:
    """Test TLD and prefix stripping logic."""

    def test_simple_com(self):
        assert _strip_domain("google-login.com") == "google-login"

    def test_simple_net(self):
        assert _strip_domain("example.net") == "example"

    def test_co_uk(self):
        assert _strip_domain("paypal.co.uk") == "paypal"

    def test_com_au(self):
        assert _strip_domain("chase.com.au") == "chase"

    def test_www_prefix(self):
        assert _strip_domain("www.google-login.com") == "google-login"

    def test_login_prefix(self):
        assert _strip_domain("login.paypal.com") == "paypal"

    def test_secure_prefix(self):
        assert _strip_domain("secure.chase.net") == "chase"

    def test_mail_prefix(self):
        assert _strip_domain("mail.google.com") == "google"

    def test_account_prefix(self):
        assert _strip_domain("account.microsoft.com") == "microsoft"

    def test_case_insensitive(self):
        assert _strip_domain("WWW.Google-Login.COM") == "google-login"

    def test_no_tld_single_label(self):
        # Edge case: single-label domain (no dots)
        assert _strip_domain("localhost") == "localhost"

    def test_whitespace_stripped(self):
        assert _strip_domain("  example.com  ") == "example"

    def test_multi_subdomain(self):
        """Multi-subdomain: all matching prefixes are stripped iteratively."""
        assert _strip_domain("login.secure.example.com") == "example"


# ---------------------------------------------------------------------------
# _levenshtein — edit distance
# ---------------------------------------------------------------------------

class TestLevenshtein:
    """Verify the Levenshtein implementation."""

    def test_identical(self):
        assert _levenshtein("google", "google") == 0

    def test_single_substitution(self):
        assert _levenshtein("googel", "google") == 2  # transposition = 2 ops

    def test_single_insertion(self):
        assert _levenshtein("gogle", "google") == 1

    def test_single_deletion(self):
        assert _levenshtein("googlee", "google") == 1

    def test_empty_strings(self):
        assert _levenshtein("", "") == 0

    def test_one_empty(self):
        assert _levenshtein("abc", "") == 3
        assert _levenshtein("", "abc") == 3

    def test_completely_different(self):
        assert _levenshtein("abc", "xyz") == 3

    def test_symmetric(self):
        assert _levenshtein("kitten", "sitting") == _levenshtein("sitting", "kitten")


# ---------------------------------------------------------------------------
# _apply_homoglyphs
# ---------------------------------------------------------------------------

class TestApplyHomoglyphs:
    """Verify homoglyph substitution."""

    def test_zero_to_o(self):
        assert _apply_homoglyphs("g00gle") == "google"

    def test_one_to_l(self):
        # 1->l fires first, replacing '1' with 'l'; subsequent 1->i has no
        # remaining '1' chars to replace
        assert _apply_homoglyphs("paypa1") == "paypal"

    def test_rn_to_m(self):
        assert _apply_homoglyphs("rnicrosoft") == "microsoft"

    def test_vv_to_w(self):
        assert _apply_homoglyphs("tvvitter") == "twitter"

    def test_no_change(self):
        assert _apply_homoglyphs("example") == "example"

    def test_multiple_substitutions(self):
        # 0->o replaces both '0's, then 1->l replaces '1'
        assert _apply_homoglyphs("g00g1e") == "google"


# ---------------------------------------------------------------------------
# score_typosquat — Brand substring detection (combo-squatting)
# ---------------------------------------------------------------------------

class TestBrandSubstring:
    """Brand name found as a substring in the domain base."""

    def test_google_security(self):
        result = score_typosquat("google-security.com", TARGETS)
        _assert_match(result, "Google")
        assert "substring" in result["reason"].lower() or "combo" in result["reason"].lower()

    def test_login_microsoft(self):
        result = score_typosquat("login-microsoft.com", TARGETS)
        _assert_match(result, "Microsoft")

    def test_paypal_verify(self):
        result = score_typosquat("paypal-verify.net", TARGETS)
        _assert_match(result, "PayPal")

    def test_chase_update(self):
        result = score_typosquat("chase-update.org", TARGETS)
        _assert_match(result, "Chase")

    def test_netflix_account(self):
        result = score_typosquat("my-netflix-login.com", TARGETS)
        _assert_match(result, "Netflix")

    def test_exact_brand_not_flagged(self):
        """google.com is the real brand — should NOT be flagged."""
        result = score_typosquat("google.com", TARGETS)
        assert result is None

    def test_case_insensitive_substring(self):
        result = score_typosquat("GOOGLE-login.COM", TARGETS)
        _assert_match(result, "Google")


# ---------------------------------------------------------------------------
# score_typosquat — Edit distance detection (typos)
# ---------------------------------------------------------------------------

class TestEditDistance:
    """Domains within edit distance <= 2 of a target brand name."""

    def test_googel(self):
        result = score_typosquat("googel.com", TARGETS)
        _assert_match(result, "Google")
        assert "edit distance" in result["reason"].lower() or "typo" in result["reason"].lower()

    def test_micorsoft(self):
        result = score_typosquat("micorsoft.com", TARGETS)
        _assert_match(result, "Microsoft")

    def test_appel(self):
        result = score_typosquat("appel.com", TARGETS)
        _assert_match(result, "Apple")

    def test_paypl(self):
        result = score_typosquat("paypl.com", TARGETS)
        _assert_match(result, "PayPal")

    def test_large_distance_not_matched(self):
        """A domain that is too different should not match."""
        result = score_typosquat("xyzabc.com", TARGETS)
        assert result is None


# ---------------------------------------------------------------------------
# score_typosquat — Homoglyph detection
# ---------------------------------------------------------------------------

class TestHomoglyphDetection:
    """Domains using character substitutions to mimic brands."""

    def test_g00gle(self):
        result = score_typosquat("g00gle.com", TARGETS)
        _assert_match(result, "Google")
        assert "homoglyph" in result["reason"].lower()

    def test_rnicrosoft(self):
        result = score_typosquat("rnicrosoft.com", TARGETS)
        _assert_match(result, "Microsoft")
        assert "homoglyph" in result["reason"].lower()

    def test_tvvitter(self):
        targets_with_twitter = ["Twitter"]
        result = score_typosquat("tvvitter.com", targets_with_twitter)
        _assert_match(result, "Twitter")

    def test_homoglyph_combo_squat(self):
        """Homoglyph normalisation reveals a brand substring."""
        result = score_typosquat("g00gle-login.com", TARGETS)
        _assert_match(result, "Google")

    def test_no_homoglyph_no_match(self):
        """Normal domain with no homoglyphs should not match."""
        result = score_typosquat("example.com", TARGETS)
        assert result is None


# ---------------------------------------------------------------------------
# score_typosquat — Legitimate domains (should return None)
# ---------------------------------------------------------------------------

class TestLegitimateDomainsReturnNone:
    """Domains unrelated to any target should return None for AI analysis."""

    def test_example_com(self):
        assert score_typosquat("example.com", TARGETS) is None

    def test_randomsite_org(self):
        assert score_typosquat("randomsite.org", TARGETS) is None

    def test_unrelated_domain(self):
        assert score_typosquat("weather-forecast.net", TARGETS) is None

    def test_very_different_domain(self):
        assert score_typosquat("zzzzzzzzz.com", TARGETS) is None

    def test_empty_domain_base(self):
        """Edge case: domain that reduces to empty string."""
        assert score_typosquat(".com", TARGETS) is None


# ---------------------------------------------------------------------------
# score_typosquat — TLD stripping integration
# ---------------------------------------------------------------------------

class TestTLDStripping:
    """Verify TLD is properly stripped before comparison."""

    def test_com_tld(self):
        result = score_typosquat("google-security.com", TARGETS)
        _assert_match(result, "Google")

    def test_net_tld(self):
        result = score_typosquat("google-security.net", TARGETS)
        _assert_match(result, "Google")

    def test_org_tld(self):
        result = score_typosquat("google-security.org", TARGETS)
        _assert_match(result, "Google")

    def test_co_uk_tld(self):
        result = score_typosquat("google-security.co.uk", TARGETS)
        _assert_match(result, "Google")

    def test_com_au_tld(self):
        result = score_typosquat("google-security.com.au", TARGETS)
        _assert_match(result, "Google")

    def test_tk_tld(self):
        result = score_typosquat("google-login.tk", TARGETS)
        _assert_match(result, "Google")


# ---------------------------------------------------------------------------
# score_typosquat — Prefix stripping integration
# ---------------------------------------------------------------------------

class TestPrefixStripping:
    """Verify common prefixes are stripped before comparison."""

    def test_www_prefix_stripped(self):
        """www.googel.com -> googel -> matches Google by edit distance."""
        result = score_typosquat("www.googel.com", TARGETS)
        _assert_match(result, "Google")

    def test_login_prefix_stripped(self):
        """login.paypal-verify.com: after TLD strip = login.paypal-verify,
        after prefix strip = paypal-verify, which contains paypal."""
        result = score_typosquat("login.paypal-verify.com", TARGETS)
        _assert_match(result, "PayPal")

    def test_secure_prefix_stripped(self):
        result = score_typosquat("secure.chase-update.com", TARGETS)
        _assert_match(result, "Chase")

    def test_mail_prefix_stripped(self):
        result = score_typosquat("mail.google-login.com", TARGETS)
        _assert_match(result, "Google")


# ---------------------------------------------------------------------------
# score_typosquat — Case insensitivity
# ---------------------------------------------------------------------------

class TestCaseInsensitivity:
    """All comparisons should be case-insensitive."""

    def test_uppercase_domain(self):
        result = score_typosquat("GOOGLE-LOGIN.COM", TARGETS)
        _assert_match(result, "Google")

    def test_mixed_case_domain(self):
        result = score_typosquat("GoOgLe-Security.Net", TARGETS)
        _assert_match(result, "Google")

    def test_uppercase_typo(self):
        result = score_typosquat("GOOGEL.COM", TARGETS)
        _assert_match(result, "Google")

    def test_uppercase_homoglyph(self):
        result = score_typosquat("G00GLE.COM", TARGETS)
        _assert_match(result, "Google")


# ---------------------------------------------------------------------------
# score_typosquat — Output format
# ---------------------------------------------------------------------------

class TestOutputFormat:
    """Matched results must conform to the expected CSV schema."""

    def test_all_required_fields(self):
        result = score_typosquat("google-login.com", TARGETS)
        assert result is not None
        assert set(result.keys()) == REQUIRED_FIELDS

    def test_domain_preserved_verbatim(self):
        """The original domain string (including TLD) must be in the output."""
        result = score_typosquat("google-login.com", TARGETS)
        assert result["domain"] == "google-login.com"

    def test_confidence_is_high(self):
        result = score_typosquat("googel.com", TARGETS)
        assert result["confidence"] == "High"

    def test_reason_is_descriptive(self):
        result = score_typosquat("g00gle.com", TARGETS)
        assert len(result["reason"]) > 10


# ---------------------------------------------------------------------------
# score_typosquat — Default targets
# ---------------------------------------------------------------------------

class TestDefaultTargets:
    """When no explicit targets list is passed, TARGETS from the module is used."""

    def test_uses_module_targets(self):
        """google-login.com should match using the default TARGETS list."""
        result = score_typosquat("google-login.com")
        _assert_match(result, "Google")

    def test_unrelated_returns_none(self):
        result = score_typosquat("example.com")
        assert result is None
