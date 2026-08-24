"""Tests for the IP-KVM discovery hunt.

Query volumes below were measured against the live Shodan API before the
queries were adopted, so a future edit that breaks syntax or reintroduces a
weak query fails here rather than silently returning nothing.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from hunt_kvm import QUERIES, BUDGET_LIMIT, load_baseline_ips, load_history_ips


class TestQuerySyntax:
    def test_no_boolean_or_or_parentheses(self):
        for q in QUERIES:
            assert " OR " not in q, f"Shodan rejects boolean OR: {q}"
            assert "(" not in q and ")" not in q, f"Shodan rejects parens: {q}"

    def test_html_filters_are_never_comma_collapsed(self):
        """Measured: comma-OR works in http.title but yields 0 in http.html."""
        for q in QUERIES:
            if "http.html:" in q:
                body = q.split("http.html:", 1)[1]
                assert '","' not in body, f"http.html cannot OR with commas: {q}"

    def test_favicon_hashes_are_one_per_query(self):
        """Measured: http.favicon.hash does not support comma-OR either."""
        for q in QUERIES:
            assert q.count("http.favicon.hash:") <= 1, q


class TestCoverage:
    def test_covers_all_kvm_products(self):
        joined = " ".join(QUERIES).lower()
        for p in ("pikvm", "tinypilot", "jetkvm", "nanokvm"):
            assert p in joined, f"no query covers {p}"

    def test_includes_body_content_queries(self):
        """http.html survives a device having its <title> renamed."""
        assert any(q.startswith("http.html:") for q in QUERIES)

    def test_includes_favicon_queries(self):
        """A rebranded device still serves the stock favicon."""
        assert any("http.favicon.hash:" in q for q in QUERIES)

    def test_does_not_rely_on_bare_jarm(self):
        """The PiKVM JARM matches 10,439 hosts globally -- it is a TLS stack
        fingerprint, not a device signature, so it must never be used alone."""
        for q in QUERIES:
            if "ssl.jarm:" in q:
                assert q.count(":") > 1, f"bare JARM query is far too broad: {q}"


class TestBudget:
    def test_query_count_fits_budget(self):
        assert len(QUERIES) <= BUDGET_LIMIT, (
            f"{len(QUERIES)} queries exceeds budget {BUDGET_LIMIT}")


class TestBaselineLoading:
    def test_loads_seed_csv_ips(self, tmp_path):
        p = tmp_path / "seed.csv"
        p.write_text("ip,port,htmltitle,tls_issuer_org,scan_date\n"
                     "1.2.3.4,443,PiKVM Login,PiKVM,2026-08-24\n"
                     "5.6.7.8,8443,PiKVM Login,PiKVM,2026-08-24\n",
                     encoding="utf-8")
        assert load_baseline_ips([str(p)]) == {"1.2.3.4", "5.6.7.8"}

    def test_loads_plain_ip_list(self, tmp_path):
        p = tmp_path / "ips.txt"
        p.write_text("# comment\n9.9.9.9\n\n8.8.8.8\n", encoding="utf-8")
        assert load_baseline_ips([str(p)]) == {"9.9.9.9", "8.8.8.8"}

    def test_missing_files_are_tolerated(self, tmp_path):
        assert load_baseline_ips([str(tmp_path / "nope.csv")]) == set()

    def test_history_missing_is_empty(self, tmp_path):
        assert load_history_ips(str(tmp_path / "nope.csv")) == set()

    def test_ipv6_is_preserved(self, tmp_path):
        """The Silent Push seed contains IPv6 hosts; dropping them would
        silently narrow the baseline and cause repeat 'new' findings."""
        p = tmp_path / "seed.csv"
        p.write_text("ip,port,htmltitle,tls_issuer_org,scan_date\n"
                     "2003:ee:37ff:226a:d624:ddff:fe96:60d1,443,PiKVM Login,,2025-01-17\n",
                     encoding="utf-8")
        assert "2003:ee:37ff:226a:d624:ddff:fe96:60d1" in load_baseline_ips([str(p)])


class TestImportable:
    def test_imports_without_api_key(self):
        """Importing must not exit -- that defect kept hunt_campaign untested."""
        import importlib
        saved = os.environ.pop("SHODAN_API_KEY", None)
        try:
            import hunt_kvm
            importlib.reload(hunt_kvm)
            assert hunt_kvm.QUERIES
        finally:
            if saved is not None:
                os.environ["SHODAN_API_KEY"] = saved


class TestExitCode:
    """The discovery job has no continue-on-error, so a non-zero exit on
    findings would fail the job and abort the pipeline. hunt_campaign.py
    carries the same rule in a comment: 'ALWAYS exit 0 so we don't break the
    build.'"""

    def test_main_returns_zero_even_with_findings(self, tmp_path, monkeypatch):
        import hunt_kvm
        from unittest.mock import MagicMock

        fake = MagicMock()
        fake.search.return_value = {
            "total": 1,
            "matches": [{"ip_str": "203.0.113.77", "port": 443, "org": "Example",
                         "location": {"country_name": "US"},
                         "http": {"title": "PiKVM Login"}}],
        }
        monkeypatch.setattr(hunt_kvm, "SHODAN_API_KEY", "k")
        monkeypatch.setattr(hunt_kvm, "HISTORY_FILE", str(tmp_path / "h.csv"))
        monkeypatch.setattr(hunt_kvm, "BASELINE_FILES", [])
        monkeypatch.setattr(sys, "argv", ["hunt_kvm.py", "--budget", "1"])

        import types
        monkeypatch.setitem(sys.modules, "shodan",
                            types.SimpleNamespace(Shodan=lambda k: fake))
        assert hunt_kvm.main() == 0, "findings must not fail the build"
