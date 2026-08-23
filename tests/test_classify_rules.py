#!/usr/bin/env python3
"""Tests for the rule-based classification pre-filter in ai_classify_web.py."""

import os
import sys

import pytest

# Allow importing from scripts/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

# classify_rules lives inside ai_classify_web which has module-level side-effects
# (LLMClient instantiation, load_dotenv).  We mock the heavy imports so the
# test suite can run without API keys or optional dependencies.
from unittest.mock import MagicMock, patch

# Stub heavy/optional imports ONLY while importing the script under test.
# These modules have import-time side effects (LLMClient instantiation,
# load_dotenv) that need no API keys here. The previous sys.modules state is
# restored immediately afterwards -- leaving the stubs in place leaks them into
# every later test module, which is what caused 66 spurious failures when the
# suite ran in alphabetical order.
_stubbed = ("shared.llm_client", "shared.flame_client", "dotenv")
_saved = {n: sys.modules.get(n) for n in _stubbed}
for _n in _stubbed:
    sys.modules.setdefault(_n, MagicMock())

try:
    import ai_classify_web  # noqa: E402
    from ai_classify_web import classify_rules  # noqa: E402
finally:
    for _n, _prev in _saved.items():
        if _prev is None:
            sys.modules.pop(_n, None)
        else:
            sys.modules[_n] = _prev


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = {"domain", "category", "reason", "confidence",
                   "flame_tp_ids", "flame_confidence"}


def _item(domain="example.com", title="", server="", status=""):
    """Build a minimal probed-domain dict."""
    return {"domain": domain, "title": title, "server": server, "status": status}


def _assert_classified(result, category, confidence=None):
    """Assert the result is a valid classification with the expected category."""
    assert result is not None, "Expected a classification but got None"
    assert set(result.keys()) == REQUIRED_FIELDS
    assert result["category"] == category
    assert result["flame_tp_ids"] == ""
    assert result["flame_confidence"] == ""
    if confidence:
        assert result["confidence"] == confidence


# ---------------------------------------------------------------------------
# Rule 1 — Error
# ---------------------------------------------------------------------------

class TestErrorRule:
    """HTTP 4xx/5xx status codes and error title phrases."""

    @pytest.mark.parametrize("status", ["400", "403", "404", "500", "502", "503", "599"])
    def test_error_status_codes(self, status):
        result = classify_rules(_item(status=status))
        _assert_classified(result, "Error", "High")
        assert f"HTTP {status}" in result["reason"]

    def test_error_status_boundary_399_not_matched(self):
        """399 is not a 4xx/5xx code — should not match the error rule."""
        result = classify_rules(_item(status="399", title="Some Page"))
        assert result is None or result["category"] != "Error"

    def test_error_status_boundary_600_not_matched(self):
        """600 is above the 5xx range — should not match."""
        result = classify_rules(_item(status="600", title="Some Page"))
        assert result is None or result["category"] != "Error"

    @pytest.mark.parametrize("title", [
        "403 Forbidden",
        "404 Not Found",
        "500 Internal Server Error",
        "502 Bad Gateway",
        "503 Service Unavailable",
        "Access Denied",
    ])
    def test_error_title_phrases(self, title):
        result = classify_rules(_item(title=title, status="200"))
        _assert_classified(result, "Error", "High")

    def test_error_title_case_insensitive(self):
        result = classify_rules(_item(title="ACCESS DENIED - Please contact admin",
                                      status="200"))
        _assert_classified(result, "Error", "High")


# ---------------------------------------------------------------------------
# Rule 2 — Unknown
# ---------------------------------------------------------------------------

class TestUnknownRule:
    """Completely empty probing data."""

    def test_all_empty(self):
        result = classify_rules(_item())
        _assert_classified(result, "Unknown", "Medium")

    def test_empty_strings(self):
        result = classify_rules(_item(title="", server="", status=""))
        _assert_classified(result, "Unknown", "Medium")

    def test_whitespace_only_treated_as_empty(self):
        result = classify_rules(_item(title="  ", server="  ", status="  "))
        _assert_classified(result, "Unknown", "Medium")

    def test_not_unknown_if_title_present(self):
        result = classify_rules(_item(title="Hello World"))
        # Should NOT be Unknown (has a title)
        assert result is None or result["category"] != "Unknown"

    def test_not_unknown_if_status_present(self):
        result = classify_rules(_item(status="200", server="nginx"))
        assert result is not None  # Matches Default (nginx with no title)
        assert result["category"] != "Unknown"


# ---------------------------------------------------------------------------
# Rule 3 — Parked
# ---------------------------------------------------------------------------

class TestParkedRule:
    """Parked / for-sale domain patterns in title."""

    @pytest.mark.parametrize("title", [
        "Domain Parked By Provider",
        "This domain is for sale",
        "Domain For Sale - Contact Us",
        "Coming Soon!",
        "Website Under Construction",
        "Buy This Domain",
        "This Domain May Be For Sale",
        "Domain Is Available",
        "GoDaddy Parking Page",
        "Namecheap Parking - Free",
        "SedoParking - example.com",
        "HugeDomains.com",
        "dan.com - domain marketplace",
        "Afternic Marketplace",
    ])
    def test_parked_titles(self, title):
        result = classify_rules(_item(title=title, status="200"))
        _assert_classified(result, "Parked", "High")

    def test_parked_case_insensitive(self):
        result = classify_rules(_item(title="COMING SOON", status="200"))
        _assert_classified(result, "Parked", "High")


# ---------------------------------------------------------------------------
# Rule 4 — Default
# ---------------------------------------------------------------------------

class TestDefaultRule:
    """Default/unconfigured web server pages."""

    @pytest.mark.parametrize("title", [
        "Welcome to nginx!",
        "Apache2 Ubuntu Default Page",
        "It Works!",
        "Test Page for the Nginx HTTP Server",
        "IIS Windows Server",
        "Default Web Page",
        "Congratulations! Your website is ready.",
        "Welcome to CentOS",
    ])
    def test_default_titles(self, title):
        result = classify_rules(_item(title=title, status="200"))
        _assert_classified(result, "Default", "High")

    def test_default_title_case_insensitive(self):
        result = classify_rules(_item(title="WELCOME TO NGINX", status="200"))
        _assert_classified(result, "Default", "High")

    @pytest.mark.parametrize("server", [
        "nginx/1.18.0",
        "Apache/2.4.41 (Ubuntu)",
        "Microsoft-IIS/10.0",
        "LiteSpeed",
        "lighttpd/1.4.55",
        "Caddy",
        "openresty/1.19.3.1",
    ])
    def test_default_server_no_title(self, server):
        """Known server header + empty title = Default."""
        result = classify_rules(_item(server=server, status="200"))
        _assert_classified(result, "Default", "High")
        assert server in result["reason"]

    def test_server_with_title_not_default_by_server_rule(self):
        """If the title is present (and not a default phrase), the server-only
        rule should not fire — the item should go to AI."""
        result = classify_rules(_item(title="My Custom App",
                                      server="nginx/1.18.0",
                                      status="200"))
        assert result is None


# ---------------------------------------------------------------------------
# Rule 5 — C2
# ---------------------------------------------------------------------------

class TestC2Rule:
    """Command-and-control indicators."""

    def test_index_of_root(self):
        result = classify_rules(_item(title="Index of /", status="200"))
        _assert_classified(result, "C2", "Medium")
        assert "Index of /" in result["reason"]

    def test_index_of_root_case_sensitive(self):
        """'Index of /' match is exact — different casing should NOT match
        this specific rule (though it may match others or fall through)."""
        result = classify_rules(_item(title="index of /", status="200"))
        # Lowercase 'index of /' should NOT match the exact C2 rule
        assert result is None or result["category"] != "C2"

    @pytest.mark.parametrize("server", [
        "Cobalt Strike 4.7",
        "Meterpreter",
        "Empire/3.8",
        "Covenant",
        "Sliver",
        "Havoc C2",
        "PoshC2",
    ])
    def test_suspicious_server_empty_title(self, server):
        result = classify_rules(_item(server=server, status="200"))
        _assert_classified(result, "C2", "Medium")
        assert server in result["reason"]

    def test_suspicious_server_needs_status_200(self):
        """Suspicious server without status 200 should not trigger C2 rule."""
        result = classify_rules(_item(server="Cobalt Strike", status="302"))
        assert result is None or result["category"] != "C2"


# ---------------------------------------------------------------------------
# Ambiguous items — should return None (sent to AI)
# ---------------------------------------------------------------------------

class TestAmbiguousItems:
    """Items that don't match any rule should return None."""

    def test_normal_website(self):
        result = classify_rules(_item(title="Acme Corp - Home",
                                      server="nginx", status="200"))
        assert result is None

    def test_phishing_like_title(self):
        result = classify_rules(_item(title="Login - Microsoft Account",
                                      server="Apache", status="200"))
        assert result is None

    def test_custom_app_title(self):
        result = classify_rules(_item(title="Dashboard - Admin Panel",
                                      server="gunicorn", status="200"))
        assert result is None

    def test_redirect_status(self):
        result = classify_rules(_item(title="", server="cloudflare",
                                      status="301"))
        assert result is None

    def test_status_200_unknown_server_no_title(self):
        """200 with an unknown (non-default, non-suspicious) server and no
        title — ambiguous, should go to AI."""
        result = classify_rules(_item(server="gunicorn/20.1.0", status="200"))
        assert result is None


# ---------------------------------------------------------------------------
# Output format validation
# ---------------------------------------------------------------------------

class TestOutputFormat:
    """All rule-classified results must have the correct fields."""

    def test_all_required_fields_present(self):
        result = classify_rules(_item(status="404"))
        assert result is not None
        assert set(result.keys()) == REQUIRED_FIELDS

    def test_domain_preserved(self):
        result = classify_rules(_item(domain="evil.test", status="500"))
        assert result["domain"] == "evil.test"

    def test_flame_fields_empty(self):
        result = classify_rules(_item(status="403"))
        assert result["flame_tp_ids"] == ""
        assert result["flame_confidence"] == ""

    def test_reason_is_descriptive(self):
        result = classify_rules(_item(status="404"))
        assert len(result["reason"]) > 5

    def test_none_fields_handled(self):
        """Ensure None values in item dict don't cause crashes."""
        item = {"domain": "test.com", "title": None, "server": None, "status": None}
        result = classify_rules(item)
        _assert_classified(result, "Unknown", "Medium")


# ---------------------------------------------------------------------------
# Rule priority / ordering
# ---------------------------------------------------------------------------

class TestRulePriority:
    """Verify that rules are evaluated in the correct order."""

    def test_error_status_beats_parked_title(self):
        """A 404 status should classify as Error even if the title says 'parked'."""
        result = classify_rules(_item(title="Domain Parked", status="404"))
        _assert_classified(result, "Error", "High")

    def test_error_title_beats_parked_title(self):
        """If title contains both '403 forbidden' and 'parked', Error wins."""
        result = classify_rules(_item(
            title="403 Forbidden - This parked domain is unavailable",
            status="200"))
        _assert_classified(result, "Error", "High")

    def test_parked_before_default(self):
        """Parked pattern in title should beat default server header."""
        result = classify_rules(_item(title="Coming Soon",
                                      server="nginx/1.18.0", status="200"))
        _assert_classified(result, "Parked", "High")
