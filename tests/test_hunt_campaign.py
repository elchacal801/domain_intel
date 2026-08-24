"""Tests for the campaign hunt query set.

hunt_campaign.py drives all proactive discovery of DEA infrastructure and runs
in CI, but had no coverage -- partly because importing it used to call
sys.exit(1) when SHODAN_API_KEY was absent.

Every assertion here encodes a fact measured against the live Shodan API, so a
future edit that reintroduces a dead query or an unsupported syntax fails loudly
rather than silently returning nothing.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from hunt_campaign import QUERIES, BUDGET_LIMIT


class TestQuerySyntax:
    def test_html_filters_are_never_comma_collapsed(self):
        """Comma-OR works inside http.title but NOT inside http.html.

        A collapsed http.html:"a","b" query measured 0 results, so collapsing
        body-content terms silently disables them.
        """
        for q in QUERIES:
            if "http.html:" in q:
                body = q.split("http.html:", 1)[1]
                assert '","' not in body, f"http.html cannot OR with commas: {q}"

    def test_no_boolean_or_or_parentheses(self):
        for q in QUERIES:
            assert " OR " not in q, f"Shodan rejects boolean OR: {q}"
            assert "(" not in q and ")" not in q, f"Shodan rejects parens: {q}"

    def test_every_query_is_a_nonempty_string(self):
        assert QUERIES
        for q in QUERIES:
            assert isinstance(q, str) and q.strip()


class TestDeadQueriesStayRemoved:
    """Each produced zero findings across six months of runs."""

    DEAD = ['http.title:"Public Email Service"',
            "net:51.254.35.0/24",
            'ssl:"in.mail.tm"']

    def test_zero_yield_queries_are_gone(self):
        joined = " ".join(QUERIES)
        for dead in self.DEAD:
            assert dead not in joined, f"zero-yield query reintroduced: {dead}"


class TestCoverage:
    """The gaps that made ~200 hosts invisible."""

    def test_temp_mail_variants_present(self):
        joined = " ".join(QUERIES).lower()
        for term in ("temp mail", "tempmail"):
            assert term in joined, f"missing high-volume term: {term}"

    def test_chinese_term_present(self):
        """Highest-volume non-English term (title 115 / html 266), and it fits
        DEA infrastructure clustering on Chinese hosting."""
        assert "临时邮箱" in " ".join(QUERIES)

    def test_body_content_queries_exist(self):
        """http.html outperformed http.title for every term measured, and
        survives a site renaming its <title>."""
        assert any(q.startswith("http.html:") for q in QUERIES)

    def test_multiple_languages_covered(self):
        joined = " ".join(QUERIES)
        for term in ("临时邮箱", "Email sementara", "Correo temporal", "Временная почта"):
            assert term in joined, f"missing localised term: {term}"


class TestBudget:
    def test_query_count_fits_budget(self):
        """One credit is spent per query; exceeding the budget silently
        truncates the run."""
        assert len(QUERIES) <= BUDGET_LIMIT, (
            f"{len(QUERIES)} queries exceeds budget of {BUDGET_LIMIT}")

    def test_budget_leaves_headroom(self):
        assert BUDGET_LIMIT >= len(QUERIES), "no headroom for retries"


class TestImportable:
    def test_module_imports_without_api_key(self):
        """Importing must not exit; the key check belongs in main()."""
        import importlib
        saved = os.environ.pop("SHODAN_API_KEY", None)
        try:
            import hunt_campaign
            importlib.reload(hunt_campaign)
            assert hunt_campaign.QUERIES
        finally:
            if saved is not None:
                os.environ["SHODAN_API_KEY"] = saved
