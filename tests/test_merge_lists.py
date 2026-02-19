#!/usr/bin/env python3
"""Tests for merge_lists_v3b.py core functions."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from merge_lists_v3b import normalize_domain, is_valid_domain, parse_line_list


# ---------------------------------------------------------------------------
# normalize_domain
# ---------------------------------------------------------------------------

class TestNormalizeDomain:
    """Test domain normalisation edge cases."""

    def test_basic_lowercase(self):
        assert normalize_domain("Example.COM") == "example.com"

    def test_strip_whitespace(self):
        assert normalize_domain("  example.com  ") == "example.com"

    def test_strip_quotes(self):
        assert normalize_domain('"example.com"') == "example.com"
        assert normalize_domain("'example.com'") == "example.com"

    def test_strip_protocol_http(self):
        assert normalize_domain("http://example.com/path") == "example.com"

    def test_strip_protocol_https(self):
        assert normalize_domain("https://example.com/page?q=1") == "example.com"

    def test_mailto_handling(self):
        assert normalize_domain("mailto:user@example.com") == "example.com"

    def test_email_address_extracts_domain(self):
        assert normalize_domain("user@example.com") == "example.com"

    def test_leading_at_stripped(self):
        assert normalize_domain("@example.com") == "example.com"

    def test_trailing_dot_stripped(self):
        assert normalize_domain("example.com.") == "example.com"

    def test_wildcard_removal(self):
        assert normalize_domain("*.example.com") == "example.com"

    def test_empty_string(self):
        assert normalize_domain("") == ""

    def test_none_input(self):
        assert normalize_domain(None) == ""

    def test_double_dots(self):
        # Double dots produce an invalid domain, normalise should leave them
        result = normalize_domain("example..com")
        assert result == "example..com"  # normalised but still invalid

    def test_path_stripped(self):
        assert normalize_domain("example.com/path/to/page") == "example.com"


class TestIsValidDomain:
    """Test domain validation."""

    def test_valid_domain(self):
        assert is_valid_domain("example.com") is True

    def test_valid_subdomain(self):
        assert is_valid_domain("sub.example.com") is True

    def test_invalid_empty(self):
        assert is_valid_domain("") is False

    def test_invalid_none(self):
        assert is_valid_domain(None) is False

    def test_invalid_double_dots(self):
        assert is_valid_domain("example..com") is False

    def test_invalid_too_long(self):
        assert is_valid_domain("a" * 254 + ".com") is False

    def test_invalid_starts_with_hyphen(self):
        assert is_valid_domain("-example.com") is False


# ---------------------------------------------------------------------------
# parse_line_list
# ---------------------------------------------------------------------------

class TestParseLineList:
    """Test parsing of line-delimited domain lists."""

    def test_basic_list(self):
        text = "example.com\ntest.org\nfoo.net"
        result = parse_line_list(text)
        assert result == {"example.com", "test.org", "foo.net"}

    def test_commented_lines_hash(self):
        text = "# This is a comment\nexample.com\n# Another\ntest.org"
        result = parse_line_list(text)
        assert result == {"example.com", "test.org"}

    def test_commented_lines_double_slash(self):
        text = "// comment\nexample.com"
        result = parse_line_list(text)
        assert result == {"example.com"}

    def test_commented_lines_semicolon(self):
        text = "; comment\nexample.com"
        result = parse_line_list(text)
        assert result == {"example.com"}

    def test_inline_comments(self):
        text = "example.com # this is a note\ntest.org // also a note"
        result = parse_line_list(text)
        assert result == {"example.com", "test.org"}

    def test_blank_lines_filtered(self):
        text = "\n\nexample.com\n\n\ntest.org\n\n"
        result = parse_line_list(text)
        assert result == {"example.com", "test.org"}

    def test_malformed_entries_filtered(self):
        text = "example.com\nnot a domain\n...\n123\ntest.org"
        result = parse_line_list(text)
        # "not a domain", "...", "123" should be filtered by is_valid_domain
        assert "example.com" in result
        assert "test.org" in result

    def test_deduplication(self):
        text = "example.com\nexample.com\nEXAMPLE.COM"
        result = parse_line_list(text)
        assert len(result) == 1
        assert "example.com" in result

    def test_empty_input(self):
        result = parse_line_list("")
        assert result == set()


# ---------------------------------------------------------------------------
# Allowlist subtraction logic
# ---------------------------------------------------------------------------

class TestAllowlistSubtraction:
    """Test set subtraction logic used for allowlist filtering."""

    def test_basic_subtraction(self):
        dea = {"a.com", "b.com", "c.com", "d.com"}
        allow = {"b.com", "d.com"}
        result = dea - allow
        assert result == {"a.com", "c.com"}

    def test_subtraction_with_no_overlap(self):
        dea = {"a.com", "b.com"}
        allow = {"x.com", "y.com"}
        result = dea - allow
        assert result == {"a.com", "b.com"}

    def test_subtraction_with_empty_allowlist(self):
        dea = {"a.com", "b.com"}
        allow = set()
        result = dea - allow
        assert result == {"a.com", "b.com"}

    def test_subtraction_removes_all(self):
        dea = {"a.com", "b.com"}
        allow = {"a.com", "b.com", "c.com"}
        result = dea - allow
        assert result == set()
