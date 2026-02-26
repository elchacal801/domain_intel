#!/usr/bin/env python3
"""Tests for enrich_dnstwist.py — dnstwist cross-reference enrichment."""

import csv
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from enrich_dnstwist import (
    load_dnstwist_lookup,
    extract_brand_name,
    check_redirects_to_brand,
    check_registrant_mismatch,
    enrich_row,
    run,
    NEW_COLUMNS,
)


# ---------------------------------------------------------------------------
# Sample dnstwist CSV data
# ---------------------------------------------------------------------------

SAMPLE_DNSTWIST_CSV = """\
domain,dns_a,dns_aaaa,dns_mx,dns_ns,fuzzer,source_target
arnazon.com,['1.2.3.4'],,,,homoglyph,amazon.com
gooogle.com,['5.6.7.8'],,,,addition,google.com
barcla1s.co.uk,['9.10.11.12'],,,,replacement,barclays.co.uk
"""


# ---------------------------------------------------------------------------
# TestLoadDnstwistLookup
# ---------------------------------------------------------------------------

class TestLoadDnstwistLookup:
    """Validate loading of dnstwist CSV into a domain lookup dict."""

    def test_loads_csv_into_lookup(self, tmp_path):
        csv_file = tmp_path / "typosquats.csv"
        csv_file.write_text(SAMPLE_DNSTWIST_CSV, encoding="utf-8")
        lookup = load_dnstwist_lookup(str(csv_file))
        assert len(lookup) == 3
        assert "arnazon.com" in lookup
        assert lookup["arnazon.com"]["fuzzer"] == "homoglyph"
        assert lookup["arnazon.com"]["source_target"] == "amazon.com"

    def test_missing_file_returns_empty(self):
        lookup = load_dnstwist_lookup("/nonexistent/path/missing.csv")
        assert lookup == {}

    def test_empty_file_returns_empty(self, tmp_path):
        csv_file = tmp_path / "empty.csv"
        csv_file.write_text("", encoding="utf-8")
        lookup = load_dnstwist_lookup(str(csv_file))
        assert lookup == {}


# ---------------------------------------------------------------------------
# TestExtractBrandName
# ---------------------------------------------------------------------------

class TestExtractBrandName:
    """Validate brand name extraction from domain strings."""

    def test_simple_domain(self):
        assert extract_brand_name("amazon.com") == "amazon"

    def test_subdomain(self):
        assert extract_brand_name("www.google.com") == "google"

    def test_two_part_tld(self):
        assert extract_brand_name("barclays.co.uk") == "barclays"

    def test_empty_string(self):
        assert extract_brand_name("") == ""


# ---------------------------------------------------------------------------
# TestCheckRedirectsToBrand
# ---------------------------------------------------------------------------

class TestCheckRedirectsToBrand:
    """Validate redirect-to-brand detection."""

    def test_redirect_to_brand(self):
        assert check_redirects_to_brand("https://amazon.com/login", "amazon.com") is True

    def test_subdomain_redirect(self):
        assert check_redirects_to_brand("https://www.amazon.com/login", "amazon.com") is True

    def test_unrelated_redirect(self):
        assert check_redirects_to_brand("https://evil-site.com/phish", "amazon.com") is False

    def test_empty_redirect(self):
        assert check_redirects_to_brand("", "amazon.com") is False


# ---------------------------------------------------------------------------
# TestCheckRegistrantMismatch
# ---------------------------------------------------------------------------

class TestCheckRegistrantMismatch:
    """Validate registrant mismatch detection."""

    def test_matching_registrant(self):
        # registrant_org contains the brand name -> no mismatch
        assert check_registrant_mismatch("Amazon Technologies Inc.", "amazon.com") is False

    def test_mismatching_registrant(self):
        assert check_registrant_mismatch("Evil Corp LLC", "amazon.com") is True

    def test_empty_defaults_true(self):
        # Empty registrant_org is suspicious -> mismatch=True
        assert check_registrant_mismatch("", "amazon.com") is True

    def test_case_insensitive(self):
        assert check_registrant_mismatch("AMAZON TECHNOLOGIES INC.", "amazon.com") is False


# ---------------------------------------------------------------------------
# TestEnrichRow
# ---------------------------------------------------------------------------

class TestEnrichRow:
    """Validate single-row enrichment logic."""

    def setup_method(self):
        self.lookup = {
            "arnazon.com": {"fuzzer": "homoglyph", "source_target": "amazon.com"},
            "gooogle.com": {"fuzzer": "addition", "source_target": "google.com"},
        }

    def test_matching_domain_full_enrichment(self):
        row = {
            "domain": "arnazon.com",
            "http_redirect_target": "https://amazon.com/landing",
            "registrant_org": "Evil Corp LLC",
            "https_status": "200",
        }
        enrich_row(row, self.lookup)
        assert row["dnstwist_match"] == "True"
        assert row["dnstwist_fuzzer"] == "homoglyph"
        assert row["dnstwist_target"] == "amazon.com"
        assert row["redirects_to_brand"] == "True"
        assert row["registrant_mismatch"] == "True"
        assert row["ssl_present"] == "True"

    def test_non_matching_domain(self):
        row = {
            "domain": "legitimate-site.com",
            "http_redirect_target": "",
            "registrant_org": "",
            "https_status": "",
        }
        enrich_row(row, self.lookup)
        assert row["dnstwist_match"] == "False"
        assert row["dnstwist_fuzzer"] == ""
        assert row["dnstwist_target"] == ""
        assert row["redirects_to_brand"] == "False"
        assert row["registrant_mismatch"] == "False"
        assert row["ssl_present"] == "False"

    def test_match_without_redirect(self):
        row = {
            "domain": "gooogle.com",
            "http_redirect_target": "",
            "registrant_org": "Google LLC",
            "https_status": "",
        }
        enrich_row(row, self.lookup)
        assert row["dnstwist_match"] == "True"
        assert row["dnstwist_fuzzer"] == "addition"
        assert row["dnstwist_target"] == "google.com"
        assert row["redirects_to_brand"] == "False"
        assert row["registrant_mismatch"] == "False"
        assert row["ssl_present"] == "False"


# ---------------------------------------------------------------------------
# TestEndToEnd
# ---------------------------------------------------------------------------

class TestEndToEnd:
    """Full CSV file enrichment end-to-end test."""

    def test_full_csv_enrichment(self, tmp_path):
        # Create dnstwist lookup CSV
        dnstwist_file = tmp_path / "typosquats.csv"
        dnstwist_file.write_text(SAMPLE_DNSTWIST_CSV, encoding="utf-8")

        # Create pipeline input CSV
        input_file = tmp_path / "input.csv"
        input_rows = [
            {
                "domain": "arnazon.com",
                "http_redirect_target": "https://amazon.com/home",
                "registrant_org": "Shady Registrations Ltd",
                "https_status": "200",
            },
            {
                "domain": "gooogle.com",
                "http_redirect_target": "",
                "registrant_org": "",
                "https_status": "301",
            },
            {
                "domain": "clean-domain.org",
                "http_redirect_target": "",
                "registrant_org": "Clean Corp",
                "https_status": "",
            },
        ]
        fieldnames = ["domain", "http_redirect_target", "registrant_org", "https_status"]
        with open(str(input_file), "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(input_rows)

        # Run enrichment
        output_file = tmp_path / "output.csv"
        match_count = run(str(input_file), str(output_file), str(dnstwist_file))

        # Verify match count
        assert match_count == 2

        # Read and verify output
        with open(str(output_file), "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 3

        # All new columns present
        for col in NEW_COLUMNS:
            assert col in rows[0], f"Missing column: {col}"

        # arnazon.com — matched, redirects to brand, registrant mismatch, SSL present
        arnazon = rows[0]
        assert arnazon["dnstwist_match"] == "True"
        assert arnazon["dnstwist_fuzzer"] == "homoglyph"
        assert arnazon["dnstwist_target"] == "amazon.com"
        assert arnazon["redirects_to_brand"] == "True"
        assert arnazon["registrant_mismatch"] == "True"
        assert arnazon["ssl_present"] == "True"

        # gooogle.com — matched, no redirect, empty registrant (mismatch=True), SSL present
        gooogle = rows[1]
        assert gooogle["dnstwist_match"] == "True"
        assert gooogle["dnstwist_fuzzer"] == "addition"
        assert gooogle["redirects_to_brand"] == "False"
        assert gooogle["registrant_mismatch"] == "True"
        assert gooogle["ssl_present"] == "True"

        # clean-domain.org — not matched
        clean = rows[2]
        assert clean["dnstwist_match"] == "False"
        assert clean["dnstwist_fuzzer"] == ""
        assert clean["ssl_present"] == "False"
