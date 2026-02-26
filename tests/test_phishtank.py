#!/usr/bin/env python3
"""Tests for enrich_phishtank.py — PhishTank & URLhaus bulk feed matching."""

import os
import sys
import csv
import gzip
import io
import tempfile

import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from enrich_phishtank import (
    extract_domain_from_url,
    parse_phishtank_csv,
    parse_urlhaus_csv,
    build_bad_domain_set,
    cross_reference_domains,
)

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_PHISHTANK = """\
phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
100001,http://evil-login.com/paypal/signin.php,http://www.phishtank.com/phish_detail.php?phish_id=100001,2026-01-01T00:00:00+00:00,yes,2026-01-01T01:00:00+00:00,yes,PayPal
100002,https://secure-banking.fake.org:8443/login,http://www.phishtank.com/phish_detail.php?phish_id=100002,2026-01-02T00:00:00+00:00,yes,2026-01-02T01:00:00+00:00,yes,Bank of America
100003,http://evil-login.com/chase/verify.html,http://www.phishtank.com/phish_detail.php?phish_id=100003,2026-01-03T00:00:00+00:00,yes,2026-01-03T01:00:00+00:00,yes,Chase
"""

SAMPLE_URLHAUS = """\
# URLhaus Database Dump (CSV)
# Columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1234","2026-01-15 10:00:00","http://malware-drop.net/payload.exe","online","2026-01-15","malware_download","elf,mozi","https://urlhaus.abuse.ch/url/1234/","reporter1"
"1235","2026-01-16 11:00:00","http://evil-login.com/stealer.zip","online","2026-01-16","malware_download","exe","https://urlhaus.abuse.ch/url/1235/","reporter2"
"1236","2026-01-17 12:00:00","http://clean-site.org/test","offline","2026-01-17","","","https://urlhaus.abuse.ch/url/1236/","reporter3"
"""


# ---------------------------------------------------------------------------
# TestExtractDomainFromUrl
# ---------------------------------------------------------------------------

class TestExtractDomainFromUrl:
    """Validate URL domain extraction."""

    def test_extracts_simple_domain(self):
        assert extract_domain_from_url("http://evil-login.com/path") == "evil-login.com"

    def test_handles_ports_and_edge_cases(self):
        assert extract_domain_from_url("https://secure.fake.org:8443/login") == "secure.fake.org"
        assert extract_domain_from_url("") == ""
        assert extract_domain_from_url("not-a-url") == ""


# ---------------------------------------------------------------------------
# TestParsePhishtankCsv
# ---------------------------------------------------------------------------

class TestParsePhishtankCsv:
    """Validate PhishTank CSV parsing."""

    def test_parses_phishtank_format(self):
        domain_map = parse_phishtank_csv(io.StringIO(SAMPLE_PHISHTANK))
        assert "evil-login.com" in domain_map
        assert "secure-banking.fake.org" in domain_map


# ---------------------------------------------------------------------------
# TestParseUrlhausCsv
# ---------------------------------------------------------------------------

class TestParseUrlhausCsv:
    """Validate URLhaus CSV parsing with comment lines."""

    def test_parses_urlhaus_with_comments(self):
        domain_map = parse_urlhaus_csv(io.StringIO(SAMPLE_URLHAUS))
        assert "malware-drop.net" in domain_map
        assert domain_map["malware-drop.net"]["threat"] == "malware_download"
        assert "evil-login.com" in domain_map


# ---------------------------------------------------------------------------
# TestCrossReferenceDomains
# ---------------------------------------------------------------------------

class TestCrossReferenceDomains:
    """Validate cross-reference matching logic."""

    def test_finds_matching_domains(self):
        phishtank_map = parse_phishtank_csv(io.StringIO(SAMPLE_PHISHTANK))
        urlhaus_map = parse_urlhaus_csv(io.StringIO(SAMPLE_URLHAUS))
        domains = ["evil-login.com", "safe-domain.org", "malware-drop.net"]
        results = cross_reference_domains(domains, phishtank_map, urlhaus_map)
        assert len(results) == 2

    def test_no_matches_returns_empty(self):
        results = cross_reference_domains(["safe.com", "clean.org"], {}, {})
        assert len(results) == 0


# ---------------------------------------------------------------------------
# TestDownloadCaching
# ---------------------------------------------------------------------------

class TestDownloadCaching:
    """Validate feed caching respects TTL."""

    def test_respects_ttl(self):
        from enrich_phishtank import _load_cached_feeds

        mock_cache = MagicMock()
        mock_cache.get.side_effect = lambda key, max_age_days=1: {
            "_feed_meta": {"phishtank_count": 10, "urlhaus_count": 5},
            "_phishtank_domains": {"evil.com": "http://evil.com/phish"},
            "_urlhaus_domains": {"bad.com": {"threat": "malware", "url": "http://bad.com/mal"}},
        }.get(key)

        result = _load_cached_feeds(mock_cache)
        assert result is not None
        phishtank_map, urlhaus_map = result
        assert "evil.com" in phishtank_map
        assert "bad.com" in urlhaus_map


# ---------------------------------------------------------------------------
# TestFingerprintModifiers
# ---------------------------------------------------------------------------

class TestFingerprintModifiers:
    """Validate that phishtank_match works as a confidence modifier."""

    def test_phishtank_match_applies_delta(self):
        from match_fingerprints import calculate_confidence

        fp = {
            "id": "FP-TEST",
            "name": "Test",
            "description": "test",
            "version": 1,
            "indicators": [],
            "confidence_base": 60,
            "confidence_modifiers": [
                {
                    "field": "phishtank_match",
                    "match_type": "exact",
                    "value": "True",
                    "delta": 15,
                },
            ],
            "flame_tp_ids": [],
            "ttl_days": 30,
        }
        row = {"domain": "evil.com", "phishtank_match": "True"}
        assert calculate_confidence(fp, row) == 75
