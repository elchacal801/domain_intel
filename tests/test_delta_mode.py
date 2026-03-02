#!/usr/bin/env python3
"""Tests for delta-only processing in ai_classify_web.py and ai_typosquat.py.

Validates that:
- Delta mode skips already-classified/analyzed domains
- --force re-processes everything
- New results are appended (not overwriting existing)
- First run (no output file) processes all domains
"""

import csv
import os
import sys

import pytest

# Allow importing from scripts/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

# Mock heavy imports before loading script modules
from unittest.mock import MagicMock

sys.modules.setdefault("shared.llm_client", MagicMock())
sys.modules.setdefault("shared.flame_client", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

import ai_classify_web  # noqa: E402
import ai_typosquat  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CLASSIFY_HEADERS = ["domain", "category", "reason", "confidence",
                    "flame_tp_ids", "flame_confidence"]

TYPOSQUAT_HEADERS = ["domain", "target", "reason", "confidence"]


def _write_classify_csv(path, rows):
    """Write a classifications CSV with headers and given rows."""
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CLASSIFY_HEADERS)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, '') for k in CLASSIFY_HEADERS})


def _write_typosquat_csv(path, rows):
    """Write a typosquats CSV with headers and given rows."""
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=TYPOSQUAT_HEADERS)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, '') for k in TYPOSQUAT_HEADERS})


def _read_csv_domains(path):
    """Read all domain values from a CSV file."""
    domains = []
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            domains.append(row.get('domain', ''))
    return domains


def _read_csv_rows(path):
    """Read all rows from a CSV file as a list of dicts."""
    with open(path, 'r', encoding='utf-8') as f:
        return list(csv.DictReader(f))


# ===========================================================================
# ai_classify_web._load_existing_domains
# ===========================================================================

class TestClassifyLoadExistingDomains:
    """Tests for ai_classify_web._load_existing_domains()."""

    def test_returns_set_of_domains(self, tmp_path):
        csv_path = str(tmp_path / "classifications.csv")
        _write_classify_csv(csv_path, [
            {"domain": "alpha.com", "category": "Parked"},
            {"domain": "beta.com", "category": "Error"},
        ])
        result = ai_classify_web._load_existing_domains(csv_path)
        assert result == {"alpha.com", "beta.com"}

    def test_returns_empty_set_when_file_missing(self, tmp_path):
        csv_path = str(tmp_path / "nonexistent.csv")
        result = ai_classify_web._load_existing_domains(csv_path)
        assert result == set()

    def test_skips_blank_domain_values(self, tmp_path):
        csv_path = str(tmp_path / "classifications.csv")
        _write_classify_csv(csv_path, [
            {"domain": "alpha.com", "category": "Parked"},
            {"domain": "", "category": "Error"},
            {"domain": "  ", "category": "Unknown"},
        ])
        result = ai_classify_web._load_existing_domains(csv_path)
        assert result == {"alpha.com"}

    def test_strips_whitespace(self, tmp_path):
        csv_path = str(tmp_path / "classifications.csv")
        _write_classify_csv(csv_path, [
            {"domain": "  alpha.com  ", "category": "Parked"},
        ])
        result = ai_classify_web._load_existing_domains(csv_path)
        assert result == {"alpha.com"}

    def test_empty_csv_with_only_headers(self, tmp_path):
        csv_path = str(tmp_path / "classifications.csv")
        _write_classify_csv(csv_path, [])
        result = ai_classify_web._load_existing_domains(csv_path)
        assert result == set()


# ===========================================================================
# ai_typosquat._load_existing_domains
# ===========================================================================

class TestTyposquatLoadExistingDomains:
    """Tests for ai_typosquat._load_existing_domains()."""

    def test_returns_set_of_domains(self, tmp_path):
        csv_path = str(tmp_path / "typosquats.csv")
        _write_typosquat_csv(csv_path, [
            {"domain": "g00gle.com", "target": "Google"},
            {"domain": "micorsoft.com", "target": "Microsoft"},
        ])
        result = ai_typosquat._load_existing_domains(csv_path)
        assert result == {"g00gle.com", "micorsoft.com"}

    def test_returns_empty_set_when_file_missing(self, tmp_path):
        csv_path = str(tmp_path / "nonexistent.csv")
        result = ai_typosquat._load_existing_domains(csv_path)
        assert result == set()

    def test_skips_blank_domain_values(self, tmp_path):
        csv_path = str(tmp_path / "typosquats.csv")
        _write_typosquat_csv(csv_path, [
            {"domain": "g00gle.com", "target": "Google"},
            {"domain": "", "target": "Microsoft"},
        ])
        result = ai_typosquat._load_existing_domains(csv_path)
        assert result == {"g00gle.com"}


# ===========================================================================
# ai_classify_web: delta mode integration (save_results + _load_existing)
# ===========================================================================

class TestClassifyDeltaIntegration:
    """End-to-end tests for delta-mode behavior with save_results."""

    def test_delta_skips_already_classified(self, tmp_path):
        """Domains in existing output should be filtered out."""
        output = str(tmp_path / "classifications.csv")
        _write_classify_csv(output, [
            {"domain": "old.com", "category": "Parked", "reason": "test",
             "confidence": "High", "flame_tp_ids": "", "flame_confidence": ""},
        ])

        existing = ai_classify_web._load_existing_domains(output)
        items = [
            {"domain": "old.com", "title": "old", "server": "", "status": "200"},
            {"domain": "new.com", "title": "new", "server": "", "status": "200"},
        ]
        filtered = [it for it in items if it.get("domain") not in existing]
        assert len(filtered) == 1
        assert filtered[0]["domain"] == "new.com"

    def test_new_results_appended_not_overwriting(self, tmp_path):
        """New save_results calls should append to existing file, not replace."""
        output = str(tmp_path / "classifications.csv")
        _write_classify_csv(output, [
            {"domain": "old.com", "category": "Parked", "reason": "test",
             "confidence": "High"},
        ])

        # Append new results
        new_results = [
            {"domain": "new.com", "category": "Error", "reason": "HTTP 404",
             "confidence": "High"},
        ]
        ai_classify_web.save_results(new_results, output)

        # Verify both old and new domains are present
        domains = _read_csv_domains(output)
        assert "old.com" in domains
        assert "new.com" in domains
        assert len(domains) == 2

    def test_force_mode_resets_file(self, tmp_path):
        """When force=True, the output file should be reset with headers."""
        output = str(tmp_path / "classifications.csv")
        _write_classify_csv(output, [
            {"domain": "old.com", "category": "Parked", "reason": "test",
             "confidence": "High"},
        ])

        # Simulate force mode: reset file with headers
        headers = CLASSIFY_HEADERS
        with open(output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()

        # Write new results
        new_results = [
            {"domain": "new.com", "category": "C2", "reason": "suspicious",
             "confidence": "Medium"},
        ]
        ai_classify_web.save_results(new_results, output)

        domains = _read_csv_domains(output)
        assert domains == ["new.com"]
        assert "old.com" not in domains

    def test_first_run_no_output_file(self, tmp_path):
        """When no output file exists, all items should be processed."""
        output = str(tmp_path / "classifications.csv")
        assert not os.path.exists(output)

        existing = ai_classify_web._load_existing_domains(output)
        assert existing == set()

        items = [
            {"domain": "a.com", "title": "A", "server": "", "status": "200"},
            {"domain": "b.com", "title": "B", "server": "", "status": "200"},
        ]
        filtered = [it for it in items if it.get("domain") not in existing]
        assert len(filtered) == 2

    def test_multiple_appends_preserve_all(self, tmp_path):
        """Multiple rounds of appending should accumulate all results."""
        output = str(tmp_path / "classifications.csv")
        _write_classify_csv(output, [
            {"domain": "first.com", "category": "Parked", "reason": "r1",
             "confidence": "High"},
        ])

        # Second batch
        ai_classify_web.save_results([
            {"domain": "second.com", "category": "Error", "reason": "r2",
             "confidence": "High"},
        ], output)

        # Third batch
        ai_classify_web.save_results([
            {"domain": "third.com", "category": "C2", "reason": "r3",
             "confidence": "Medium"},
        ], output)

        domains = _read_csv_domains(output)
        assert domains == ["first.com", "second.com", "third.com"]


# ===========================================================================
# ai_typosquat: delta mode integration (save_matches + _load_existing)
# ===========================================================================

class TestTyposquatDeltaIntegration:
    """End-to-end tests for delta-mode behavior with save_matches."""

    def test_delta_skips_already_analyzed(self, tmp_path):
        """Domains in existing output should be filtered out."""
        output = str(tmp_path / "typosquats.csv")
        _write_typosquat_csv(output, [
            {"domain": "g00gle.com", "target": "Google", "reason": "homoglyph",
             "confidence": "High"},
        ])

        existing = ai_typosquat._load_existing_domains(output)
        all_domains = ["g00gle.com", "micorsoft.com", "normal.com"]
        filtered = [d for d in all_domains if d not in existing]
        assert len(filtered) == 2
        assert "g00gle.com" not in filtered
        assert "micorsoft.com" in filtered

    def test_new_results_appended_not_overwriting(self, tmp_path):
        """New save_matches calls should append to existing file."""
        output = str(tmp_path / "typosquats.csv")
        _write_typosquat_csv(output, [
            {"domain": "g00gle.com", "target": "Google", "reason": "homoglyph",
             "confidence": "High"},
        ])

        # Append new matches
        new_matches = [
            {"domain": "micorsoft.com", "target": "Microsoft",
             "reason": "typo", "confidence": "High"},
        ]
        ai_typosquat.save_matches(new_matches, output)

        domains = _read_csv_domains(output)
        assert "g00gle.com" in domains
        assert "micorsoft.com" in domains
        assert len(domains) == 2

    def test_force_mode_resets_file(self, tmp_path):
        """When force=True, the output file should be reset."""
        output = str(tmp_path / "typosquats.csv")
        _write_typosquat_csv(output, [
            {"domain": "g00gle.com", "target": "Google", "reason": "homoglyph",
             "confidence": "High"},
        ])

        # Simulate force mode: reset file with headers
        headers = TYPOSQUAT_HEADERS
        with open(output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()

        # Write new matches
        new_matches = [
            {"domain": "micorsoft.com", "target": "Microsoft",
             "reason": "typo", "confidence": "High"},
        ]
        ai_typosquat.save_matches(new_matches, output)

        domains = _read_csv_domains(output)
        assert domains == ["micorsoft.com"]
        assert "g00gle.com" not in domains

    def test_first_run_no_output_file(self, tmp_path):
        """When no output file exists, all domains should be processed."""
        output = str(tmp_path / "typosquats.csv")
        assert not os.path.exists(output)

        existing = ai_typosquat._load_existing_domains(output)
        assert existing == set()

        all_domains = ["a.com", "b.com", "c.com"]
        filtered = [d for d in all_domains if d not in existing]
        assert len(filtered) == 3

    def test_multiple_appends_preserve_all(self, tmp_path):
        """Multiple rounds of appending should accumulate all results."""
        output = str(tmp_path / "typosquats.csv")
        _write_typosquat_csv(output, [
            {"domain": "first.com", "target": "Google", "reason": "r1",
             "confidence": "High"},
        ])

        ai_typosquat.save_matches([
            {"domain": "second.com", "target": "Microsoft", "reason": "r2",
             "confidence": "High"},
        ], output)

        ai_typosquat.save_matches([
            {"domain": "third.com", "target": "Apple", "reason": "r3",
             "confidence": "Medium"},
        ], output)

        domains = _read_csv_domains(output)
        assert domains == ["first.com", "second.com", "third.com"]


# ===========================================================================
# Edge cases
# ===========================================================================

class TestDeltaEdgeCases:
    """Edge cases for delta processing."""

    def test_classify_duplicate_domains_in_existing(self, tmp_path):
        """Duplicate domains in existing CSV should be handled gracefully."""
        csv_path = str(tmp_path / "classifications.csv")
        _write_classify_csv(csv_path, [
            {"domain": "dup.com", "category": "Parked"},
            {"domain": "dup.com", "category": "Error"},
        ])
        result = ai_classify_web._load_existing_domains(csv_path)
        # Sets deduplicate automatically
        assert result == {"dup.com"}

    def test_typosquat_duplicate_domains_in_existing(self, tmp_path):
        """Duplicate domains in existing CSV should be handled gracefully."""
        csv_path = str(tmp_path / "typosquats.csv")
        _write_typosquat_csv(csv_path, [
            {"domain": "dup.com", "target": "Google"},
            {"domain": "dup.com", "target": "Microsoft"},
        ])
        result = ai_typosquat._load_existing_domains(csv_path)
        assert result == {"dup.com"}

    def test_classify_large_existing_set(self, tmp_path):
        """Delta filtering should work with a large number of existing domains."""
        csv_path = str(tmp_path / "classifications.csv")
        rows = [{"domain": f"domain-{i}.com", "category": "Parked"}
                for i in range(500)]
        _write_classify_csv(csv_path, rows)

        existing = ai_classify_web._load_existing_domains(csv_path)
        assert len(existing) == 500

        # Filter: only one new domain out of 501
        items = [{"domain": f"domain-{i}.com"} for i in range(501)]
        filtered = [it for it in items if it.get("domain") not in existing]
        assert len(filtered) == 1
        assert filtered[0]["domain"] == "domain-500.com"
