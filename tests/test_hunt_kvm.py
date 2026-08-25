"""Tests for the IP-KVM discovery hunt.

Query volumes below were measured against the live Shodan API before the
queries were adopted, so a future edit that breaks syntax or reintroduces a
weak query fails here rather than silently returning nothing.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from hunt_kvm import (QUERIES, BUDGET_LIMIT, load_baseline_ips, load_history_ips,
                      is_routable_ip, log_hit)


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


class TestPagination:
    """api.search() returns only the first 100 matches. Our queries expose
    ~39,000 hosts but a run retrieved ~1,500, so coverage plateaued as soon as
    dedup caught up with page 1. Credits are spent per page, so the page cap is
    the real budget control."""

    def _api(self, total, per_page=100):
        from unittest.mock import MagicMock
        api = MagicMock()
        pages = []
        made = 0
        while made < total:
            n = min(per_page, total - made)
            pages.append({"total": total,
                          "matches": [{"ip_str": f"10.{made//65536%256}.{(made//256)%256}.{made%256}",
                                       "port": 443, "org": "x",
                                       "location": {"country_name": "US"},
                                       "http": {"title": "PiKVM"}}
                                      for made in range(made, made + n)]})
            made += n
        api.search.side_effect = pages + [{"total": total, "matches": []}] * 5
        return api

    def test_fetches_beyond_the_first_page(self, tmp_path, monkeypatch):
        import types, sys, hunt_kvm
        api = self._api(250)
        monkeypatch.setattr(hunt_kvm, "SHODAN_API_KEY", "k")
        monkeypatch.setattr(hunt_kvm, "HISTORY_FILE", str(tmp_path / "h.csv"))
        monkeypatch.setattr(hunt_kvm, "BASELINE_FILES", [])
        monkeypatch.setattr(hunt_kvm, "QUERIES", ['http.title:"pikvm"'])
        monkeypatch.setattr(sys, "argv",
                            ["hunt_kvm.py", "--budget", "10", "--pages", "3"])
        monkeypatch.setitem(sys.modules, "shodan",
                            types.SimpleNamespace(Shodan=lambda k: api))
        assert hunt_kvm.main() == 0
        assert api.search.call_count >= 2, "must request more than one page"

    def test_page_cap_is_respected(self, tmp_path, monkeypatch):
        import types, sys, hunt_kvm
        api = self._api(1000)
        monkeypatch.setattr(hunt_kvm, "SHODAN_API_KEY", "k")
        monkeypatch.setattr(hunt_kvm, "HISTORY_FILE", str(tmp_path / "h.csv"))
        monkeypatch.setattr(hunt_kvm, "BASELINE_FILES", [])
        monkeypatch.setattr(hunt_kvm, "QUERIES", ['http.title:"pikvm"'])
        monkeypatch.setattr(sys, "argv",
                            ["hunt_kvm.py", "--budget", "50", "--pages", "2"])
        monkeypatch.setitem(sys.modules, "shodan",
                            types.SimpleNamespace(Shodan=lambda k: api))
        hunt_kvm.main()
        assert api.search.call_count <= 2, "must not exceed --pages per query"


class TestHuntThrottle:
    """A 390-page run shares Shodan's ~1 req/s limit with the enrichment sweep.
    Without pacing, a 429 breaks out of the page loop and silently truncates
    that query's retrieval -- the failure looks like "fewer results exist"."""

    def test_hunt_paces_requests(self, tmp_path, monkeypatch):
        import types, sys, hunt_kvm
        from unittest.mock import MagicMock, patch
        api = MagicMock()
        api.search.return_value = {"total": 250, "matches": [
            {"ip_str": f"10.0.0.{i}", "port": 443, "org": "x",
             "location": {"country_name": "US"}, "http": {"title": "PiKVM"}}
            for i in range(100)]}
        monkeypatch.setattr(hunt_kvm, "SHODAN_API_KEY", "k")
        monkeypatch.setattr(hunt_kvm, "HISTORY_FILE", str(tmp_path / "h.csv"))
        monkeypatch.setattr(hunt_kvm, "BASELINE_FILES", [])
        monkeypatch.setattr(hunt_kvm, "QUERIES", ['http.title:"pikvm"'])
        monkeypatch.setattr(sys, "argv", ["hunt_kvm.py", "--budget", "5", "--pages", "3"])
        monkeypatch.setitem(sys.modules, "shodan",
                            types.SimpleNamespace(Shodan=lambda k: api))
        slept = []
        with patch("hunt_kvm.time.sleep", side_effect=slept.append):
            hunt_kvm.main()
        assert slept, "consecutive pages must be paced"


class TestRateLimitResilience:
    """A full-retrieval run hit 'Rate limit reached' and returned 0 total for
    the 25,360-host ScreenConnect query -- a rate limit was indistinguishable
    from an empty result. Two causes: only pages 2+ were paced, so 18 queries
    meant 18 unthrottled first-page bursts; and any error broke the whole page
    loop, so one transient 429 killed 254 pages of retrieval."""

    def _run(self, monkeypatch, tmp_path, api, argv):
        import types, sys, hunt_kvm
        monkeypatch.setattr(hunt_kvm, "SHODAN_API_KEY", "k")
        monkeypatch.setattr(hunt_kvm, "HISTORY_FILE", str(tmp_path / "h.csv"))
        monkeypatch.setattr(hunt_kvm, "BASELINE_FILES", [])
        monkeypatch.setattr(hunt_kvm, "QUERIES", ['http.title:"pikvm"'])
        monkeypatch.setattr(sys, "argv", argv)
        monkeypatch.setitem(sys.modules, "shodan",
                            types.SimpleNamespace(Shodan=lambda k: api))
        return hunt_kvm

    def test_first_page_is_also_paced(self, tmp_path, monkeypatch):
        from unittest.mock import MagicMock, patch
        api = MagicMock()
        api.search.return_value = {"total": 10, "matches": []}
        hk = self._run(monkeypatch, tmp_path, api,
                       ["hunt_kvm.py", "--budget", "5", "--pages", "1"])
        slept = []
        with patch("hunt_kvm.time.sleep", side_effect=slept.append):
            hk.main()
        assert slept, "the first request of a query must be paced too"

    def test_rate_limit_is_retried_not_fatal(self, tmp_path, monkeypatch):
        from unittest.mock import MagicMock, patch
        api = MagicMock()
        page = {"total": 250, "matches": [
            {"ip_str": f"10.1.1.{i}", "port": 443, "org": "x",
             "location": {"country_name": "US"}, "http": {"title": "PiKVM"}}
            for i in range(100)]}
        api.search.side_effect = [
            Exception("Rate limit reached. Please throttle your requests"),
            page,
            {"total": 250, "matches": page["matches"][:50]},
        ]
        hk = self._run(monkeypatch, tmp_path, api,
                       ["hunt_kvm.py", "--budget", "10", "--pages", "2"])
        with patch("hunt_kvm.time.sleep"):
            assert hk.main() == 0
        assert api.search.call_count >= 2, "a 429 must be retried, not abandoned"

    def test_non_rate_limit_error_still_stops_the_query(self, tmp_path, monkeypatch):
        """Only rate limits are worth retrying; a malformed query is not."""
        from unittest.mock import MagicMock, patch
        api = MagicMock()
        api.search.side_effect = Exception("Invalid query")
        hk = self._run(monkeypatch, tmp_path, api,
                       ["hunt_kvm.py", "--budget", "10", "--pages", "5"])
        with patch("hunt_kvm.time.sleep"):
            hk.main()
        assert api.search.call_count <= 2, "must not retry a permanent error"


class TestBogonFiltering:
    """Shodan's index contains records with unroutable addresses.

    A single 2026-08-24 `http.title:"pikvm"` batch contributed 351 rows in
    10.0.0.0/24 and 10.1.1.0/24, all org='x'. They cannot be real internet
    hosts, and because they are densely packed they dominated /24 clustering
    -- the top two "clusters" were both artifacts.
    """

    def test_public_addresses_are_routable(self):
        for ip in ("8.8.8.8", "1.13.21.238", "45.154.159.10"):
            assert is_routable_ip(ip) is True, ip

    def test_rfc1918_is_rejected(self):
        for ip in ("10.0.0.0", "10.1.1.100", "192.168.1.1", "172.16.0.1"):
            assert is_routable_ip(ip) is False, ip

    def test_loopback_linklocal_and_unspecified_are_rejected(self):
        for ip in ("127.0.0.1", "169.254.1.1", "0.0.0.0", "255.255.255.255"):
            assert is_routable_ip(ip) is False, ip

    def test_cgnat_is_rejected(self):
        assert is_routable_ip("100.64.0.1") is False

    def test_global_ipv6_is_kept(self):
        """The Silent Push seed is largely IPv6; filtering it would make the
        hunt re-report those hosts as new on every run."""
        assert is_routable_ip("2003:ee:37ff:226a:d624:ddff:fe96:60d1") is True

    def test_ipv6_loopback_and_ula_are_rejected(self):
        for ip in ("::1", "fd00::1", "fe80::1"):
            assert is_routable_ip(ip) is False, ip

    def test_garbage_is_rejected_not_raised(self):
        for value in ("", "not-an-ip", "10.0.0", None):
            assert is_routable_ip(value) is False, repr(value)

    def test_log_hit_skips_bogons(self, tmp_path):
        """The filter must sit at the write, so no path can reintroduce them."""
        path = tmp_path / "hist.csv"
        log_hit({"ip_str": "10.0.0.5", "port": 443, "org": "x"}, "q", str(path))
        assert not path.exists(), "bogon was written to history"
        log_hit({"ip_str": "8.8.8.8", "port": 443, "org": "real"}, "q", str(path))
        assert path.exists()
        assert "8.8.8.8" in path.read_text(encoding="utf-8")

    def test_load_history_ignores_bogons(self, tmp_path):
        """Existing files already contain 351 of them; reads must exclude."""
        path = tmp_path / "hist.csv"
        path.write_text(
            "first_seen,ip,port,query,product,org,country,title\n"
            "2026-08-24 14:58:14,10.0.0.0,443,q,,x,US,PiKVM\n"
            "2026-08-24 14:58:14,8.8.8.8,443,q,,real,US,PiKVM\n",
            encoding="utf-8",
        )
        assert load_history_ips(str(path)) == {"8.8.8.8"}
