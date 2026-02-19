#!/usr/bin/env python3
"""Tests for shared.sanitize module."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from shared.sanitize import sanitize_csv_value


class TestSanitizeCsvValue:
    """Test CSV formula injection protection."""

    def test_equals_prefix(self):
        assert sanitize_csv_value("=CMD()") == "'=CMD()"

    def test_plus_prefix(self):
        assert sanitize_csv_value("+cmd") == "'+cmd"

    def test_minus_prefix(self):
        assert sanitize_csv_value("-formula") == "'-formula"

    def test_at_prefix(self):
        assert sanitize_csv_value("@sum") == "'@sum"

    def test_tab_prefix(self):
        assert sanitize_csv_value("\tcmd") == "'\tcmd"

    def test_normal_value_unchanged(self):
        assert sanitize_csv_value("normal value") == "normal value"

    def test_empty_string_unchanged(self):
        assert sanitize_csv_value("") == ""

    def test_numeric_string_unchanged(self):
        assert sanitize_csv_value("12345") == "12345"

    def test_url_unchanged(self):
        assert sanitize_csv_value("https://example.com") == "https://example.com"

    def test_domain_unchanged(self):
        assert sanitize_csv_value("example.com") == "example.com"

    def test_nested_formula_no_prefix(self):
        """Only the first character matters — formula chars mid-string are fine."""
        assert sanitize_csv_value("hello=world") == "hello=world"

    def test_non_string_passthrough(self):
        """Non-string types should be returned as-is."""
        assert sanitize_csv_value(None) is None
        assert sanitize_csv_value(42) == 42
