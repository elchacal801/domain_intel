#!/usr/bin/env python3
"""Tests for enrich_securitytrails.py — SecurityTrails manual investigation tool."""

import sys
import os
import csv
import json
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from enrich_securitytrails import (
    parse_dns_history,
    parse_whois_history,
    format_console_output,
    build_result_row,
    ST_COLUMNS,
)


# ---------------------------------------------------------------------------
# Sample API Responses
# ---------------------------------------------------------------------------

SAMPLE_DNS_A = {
    "records": [
        {"values": [{"ip": "1.2.3.4"}], "first_seen": "2019-03-15", "last_seen": "2024-05-31"},
        {"values": [{"ip": "5.6.7.8"}], "first_seen": "2024-06-01", "last_seen": "2025-11-20"},
    ]
}

SAMPLE_DNS_MX = {
    "records": [
        {"values": [{"host": "mx1.google.com"}], "first_seen": "2019-03-15", "last_seen": "2023-01-09"},
        {"values": [{"host": "mail.protonmail.ch"}], "first_seen": "2023-01-10", "last_seen": "2025-11-20"},
    ]
}

SAMPLE_DNS_NS = {
    "records": [
        {"values": [{"nameserver": "ns1.registrar-servers.com"}], "first_seen": "2019-03-15", "last_seen": "2025-10-01"},
    ]
}

SAMPLE_WHOIS = {
    "result": {
        "items": [
            {"registrar_name": "GoDaddy", "created_date": "2019-03-15"},
            {"registrar_name": "Namecheap", "created_date": "2023-06-01"},
            {"registrar_name": "PDR Ltd", "created_date": "2025-09-15"},
        ]
    }
}


# ---------------------------------------------------------------------------
# TestParseDnsHistory
# ---------------------------------------------------------------------------

class TestParseDnsHistory:
    """Verify parsing of SecurityTrails DNS history responses."""

    def test_parse_a_records(self):
        result = parse_dns_history(SAMPLE_DNS_A, "a")
        assert result["unique_count"] == 2
        assert result["first_seen"] == "2019-03-15"
        assert len(result["entries"]) == 2
        assert result["entries"][0]["value"] == "1.2.3.4"

    def test_parse_mx_records(self):
        result = parse_dns_history(SAMPLE_DNS_MX, "mx")
        assert result["unique_count"] == 2
        assert result["entries"][1]["value"] == "mail.protonmail.ch"
        assert result["last_change"] == "2023-01-10"

    def test_parse_ns_records(self):
        result = parse_dns_history(SAMPLE_DNS_NS, "ns")
        assert result["unique_count"] == 1

    def test_parse_empty_response(self):
        result = parse_dns_history({"records": []}, "a")
        assert result["unique_count"] == 0
        assert result["entries"] == []
        assert result["first_seen"] == ""

    def test_parse_none_response(self):
        result = parse_dns_history(None, "a")
        assert result["unique_count"] == 0


# ---------------------------------------------------------------------------
# TestParseWhoisHistory
# ---------------------------------------------------------------------------

class TestParseWhoisHistory:
    """Verify parsing of SecurityTrails WHOIS history responses."""

    def test_parse_whois_registrar_count(self):
        result = parse_whois_history(SAMPLE_WHOIS)
        assert result["registrar_changes"] == 3

    def test_parse_whois_entries(self):
        result = parse_whois_history(SAMPLE_WHOIS)
        assert len(result["entries"]) == 3
        assert result["entries"][0]["registrar"] == "GoDaddy"

    def test_parse_empty_whois(self):
        result = parse_whois_history({"result": {"items": []}})
        assert result["registrar_changes"] == 0
        assert result["entries"] == []

    def test_parse_none_whois(self):
        result = parse_whois_history(None)
        assert result["registrar_changes"] == 0


# ---------------------------------------------------------------------------
# TestBuildResultRow
# ---------------------------------------------------------------------------

class TestBuildResultRow:
    """Verify building the output row from parsed data."""

    def test_builds_complete_row(self):
        dns_a = parse_dns_history(SAMPLE_DNS_A, "a")
        dns_mx = parse_dns_history(SAMPLE_DNS_MX, "mx")
        dns_ns = parse_dns_history(SAMPLE_DNS_NS, "ns")
        whois = parse_whois_history(SAMPLE_WHOIS)

        row = build_result_row("evil.com", dns_a, dns_mx, dns_ns, whois)
        assert row["domain"] == "evil.com"
        assert row["st_dns_history_count"] == "2"
        assert row["st_registrar_changes"] == "3"
        assert "google.com" in row["st_mx_history"]
        assert "protonmail.ch" in row["st_mx_history"]
        assert row["st_first_seen"] == "2019-03-15"
        assert row["st_mx_change_date"] == "2023-01-10"

    def test_builds_row_with_empty_data(self):
        dns_a = parse_dns_history(None, "a")
        dns_mx = parse_dns_history(None, "mx")
        dns_ns = parse_dns_history(None, "ns")
        whois = parse_whois_history(None)

        row = build_result_row("empty.com", dns_a, dns_mx, dns_ns, whois)
        assert row["domain"] == "empty.com"
        assert row["st_dns_history_count"] == "0"
        assert row["st_registrar_changes"] == "0"
        assert row["st_mx_history"] == ""
        assert row["st_first_seen"] == ""
        assert row["st_mx_change_date"] == ""


# ---------------------------------------------------------------------------
# TestFormatConsoleOutput
# ---------------------------------------------------------------------------

class TestFormatConsoleOutput:
    """Verify console output formatting."""

    def test_output_contains_domain(self):
        dns_a = parse_dns_history(SAMPLE_DNS_A, "a")
        dns_mx = parse_dns_history(SAMPLE_DNS_MX, "mx")
        dns_ns = parse_dns_history(SAMPLE_DNS_NS, "ns")
        whois = parse_whois_history(SAMPLE_WHOIS)
        output = format_console_output("evil.com", dns_a, dns_mx, dns_ns, whois, remaining=46)
        assert "evil.com" in output
        assert "46" in output
        assert "1.2.3.4" in output
        assert "GoDaddy" in output


# ---------------------------------------------------------------------------
# TestCSVAppend
# ---------------------------------------------------------------------------

class TestCSVAppend:
    """Verify CSV save functionality."""

    def test_creates_new_csv_with_headers(self, tmp_path):
        from enrich_securitytrails import save_to_csv
        csv_path = str(tmp_path / "investigations.csv")
        row = {
            "domain": "evil.com",
            "st_dns_history_count": "2",
            "st_registrar_changes": "3",
            "st_mx_history": "google.com;protonmail.ch",
            "st_first_seen": "2019-03-15",
            "st_mx_change_date": "2023-01-10",
        }
        save_to_csv(row, csv_path)

        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["domain"] == "evil.com"

    def test_appends_to_existing_csv(self, tmp_path):
        from enrich_securitytrails import save_to_csv
        csv_path = str(tmp_path / "investigations.csv")
        row1 = {"domain": "a.com", "st_dns_history_count": "1", "st_registrar_changes": "1",
                "st_mx_history": "", "st_first_seen": "", "st_mx_change_date": ""}
        row2 = {"domain": "b.com", "st_dns_history_count": "2", "st_registrar_changes": "2",
                "st_mx_history": "", "st_first_seen": "", "st_mx_change_date": ""}
        save_to_csv(row1, csv_path)
        save_to_csv(row2, csv_path)

        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2


# ---------------------------------------------------------------------------
# TestBudgetIntegration
# ---------------------------------------------------------------------------

class TestBudgetIntegration:
    """Verify that the script respects the quota tracker."""

    def test_budget_check_mode(self, tmp_path):
        """--budget-check should print remaining and exit without API calls."""
        from shared.api_budget import PersistentQuotaTracker
        db = str(tmp_path / "budget.db")
        tracker = PersistentQuotaTracker(db_path=db, max_queries=50, window_days=30)
        tracker.record_usage("securitytrails", "old.com", cost=4)
        assert tracker.get_remaining() == 46
        tracker.close()
