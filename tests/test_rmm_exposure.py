"""Tests for IP-KVM / remote-management exposure detection.

Signatures are drawn from runZero's IP-KVM survey (HTTP titles and favicon
hashes) and vendor default ports. The classifier is deliberately pure -- it
takes a Shodan host record and returns findings -- so it needs no API access.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from enrich_rmm_exposure import classify_host, KVM_SIGNATURES, RMM_SIGNATURES


def host(*services, ip="203.0.113.10", ports=None):
    """Build a minimal Shodan host record."""
    return {
        "ip_str": ip,
        "ports": ports if ports is not None else [s.get("port") for s in services],
        "data": list(services),
    }


def svc(port, product=None, title=None, favicon=None):
    entry = {"port": port}
    if product:
        entry["product"] = product
    http = {}
    if title:
        http["title"] = title
    if favicon:
        http["favicon"] = {"hash": favicon}
    if http:
        entry["http"] = http
    return entry


class TestKVMDetection:
    def test_pikvm_by_title(self):
        r = classify_host(host(svc(443, title="PiKVM - Login")))
        assert r["kvm_detected"] is True
        assert "PiKVM" in r["kvm_products"]

    def test_pikvm_alternate_title_spelling(self):
        """runZero documents both 'PiKVM' and 'Pi-KVM'."""
        r = classify_host(host(svc(443, title="Pi-KVM Web Terminal")))
        assert r["kvm_detected"] is True
        assert "PiKVM" in r["kvm_products"]

    def test_tinypilot_by_favicon_hash(self):
        """Title can be customised; the favicon hash still gives it away."""
        r = classify_host(host(svc(80, title="Server Room", favicon=-996415781)))
        assert r["kvm_detected"] is True
        assert "TinyPilot" in r["kvm_products"]

    def test_jetkvm_by_title(self):
        r = classify_host(host(svc(80, title="JetKVM")))
        assert r["kvm_detected"] is True
        assert "JetKVM" in r["kvm_products"]

    def test_guacamole_by_title(self):
        r = classify_host(host(svc(8080, title="Apache Guacamole")))
        assert r["kvm_detected"] is True
        assert "Apache Guacamole" in r["kvm_products"]

    def test_title_match_is_case_insensitive(self):
        r = classify_host(host(svc(443, title="pikvm")))
        assert r["kvm_detected"] is True


class TestRMMDetection:
    def test_rustdesk_by_port(self):
        r = classify_host(host(svc(21116)))
        assert r["rmm_detected"] is True
        assert "RustDesk" in r["rmm_products"]

    def test_anydesk_by_port(self):
        r = classify_host(host(svc(7070)))
        assert r["rmm_detected"] is True
        assert "AnyDesk" in r["rmm_products"]

    def test_teamviewer_by_port(self):
        r = classify_host(host(svc(5938)))
        assert r["rmm_detected"] is True
        assert "TeamViewer" in r["rmm_products"]

    def test_product_banner_match(self):
        r = classify_host(host(svc(443, product="TeamViewer")))
        assert r["rmm_detected"] is True
        assert "TeamViewer" in r["rmm_products"]


class TestNoFalsePositives:
    def test_ordinary_webserver_is_clean(self):
        r = classify_host(host(svc(80, product="nginx", title="Welcome to nginx!"),
                               svc(443, product="nginx")))
        assert r["kvm_detected"] is False
        assert r["rmm_detected"] is False
        assert r["kvm_products"] == ""
        assert r["rmm_products"] == ""

    def test_empty_host_record_is_clean(self):
        r = classify_host({"ip_str": "203.0.113.1", "ports": [], "data": []})
        assert r["kvm_detected"] is False
        assert r["rmm_detected"] is False

    def test_missing_data_key_does_not_raise(self):
        r = classify_host({"ip_str": "203.0.113.1"})
        assert r["kvm_detected"] is False

    def test_unrelated_high_port_is_clean(self):
        """A high port that is not a known RMM default must not match."""
        r = classify_host(host(svc(21118)))
        assert r["rmm_detected"] is False


class TestCombinedFindings:
    def test_kvm_and_rmm_together(self):
        r = classify_host(host(svc(443, title="PiKVM"), svc(21116)))
        assert r["kvm_detected"] is True
        assert r["rmm_detected"] is True

    def test_multiple_products_are_all_listed(self):
        r = classify_host(host(svc(7070), svc(5938)))
        assert "AnyDesk" in r["rmm_products"]
        assert "TeamViewer" in r["rmm_products"]

    def test_products_are_deduplicated(self):
        r = classify_host(host(svc(21115), svc(21116), svc(21117)))
        assert r["rmm_products"].count("RustDesk") == 1

    def test_evidence_records_what_matched(self):
        """A finding must be explainable without re-querying Shodan."""
        r = classify_host(host(svc(443, title="PiKVM - Login")))
        assert "443" in r["exposure_evidence"]
        assert "PiKVM" in r["exposure_evidence"]


class TestSignatureTables:
    def test_signature_tables_are_populated(self):
        assert len(KVM_SIGNATURES) >= 6, "expected the runZero IP-KVM set"
        assert len(RMM_SIGNATURES) >= 4

    def test_every_kvm_signature_has_a_matcher(self):
        for name, sig in KVM_SIGNATURES.items():
            assert sig.get("titles") or sig.get("favicons"), f"{name} has no matcher"

    def test_every_rmm_signature_has_a_matcher(self):
        for name, sig in RMM_SIGNATURES.items():
            assert sig.get("ports") or sig.get("products"), f"{name} has no matcher"


class TestSearchQuerySyntax:
    """Shodan supports neither OR nor parentheses; alternatives are comma-separated.

    A live run against five operator ASNs returned
    'APIError: The search query was invalid' for every one, because the query
    was built with ' OR ' and wrapped in parentheses.
    """

    def test_query_uses_no_boolean_or(self):
        from enrich_rmm_exposure import kvm_search_query
        q = kvm_search_query()
        assert " OR " not in q, f"Shodan rejects boolean OR: {q}"
        assert "(" not in q and ")" not in q, f"Shodan rejects parentheses: {q}"

    def test_query_is_a_single_comma_separated_title_filter(self):
        from enrich_rmm_exposure import kvm_search_query
        q = kvm_search_query()
        assert q.count("http.title:") == 1, f"expected one filter, got: {q}"
        assert '"pikvm"' in q and '"tinypilot"' in q


class TestAnnotateCsv:
    """Findings must be joinable onto domain rows, which is what the
    fingerprint engine matches against (see FP-0010 consuming
    proxy_detected/proxy_type from enrich_proxy_check.py)."""

    def _domains(self, tmp_path):
        import csv
        p = tmp_path / "domains.csv"
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["domain", "a_record"])
            w.writeheader()
            w.writerow({"domain": "bad.example", "a_record": "203.0.113.10"})
            w.writerow({"domain": "clean.example", "a_record": "203.0.113.99"})
            w.writerow({"domain": "noip.example", "a_record": ""})
        return str(p)

    def test_annotates_matching_rows_and_preserves_others(self, tmp_path):
        import csv
        from enrich_rmm_exposure import annotate_csv

        src = self._domains(tmp_path)
        out = str(tmp_path / "out.csv")
        findings = {
            "203.0.113.10": {
                "kvm_detected": True, "kvm_products": "PiKVM",
                "rmm_detected": False, "rmm_products": "",
                "exposure_evidence": "443:PiKVM(title)",
            }
        }
        n = annotate_csv(src, out, findings, ip_column="a_record")

        rows = {r["domain"]: r for r in csv.DictReader(open(out, encoding="utf-8"))}
        assert n == 1
        assert rows["bad.example"]["kvm_detected"] == "yes"
        assert rows["bad.example"]["kvm_products"] == "PiKVM"
        assert rows["bad.example"]["exposure_evidence"] == "443:PiKVM(title)"
        # untouched rows keep their data and get empty, not missing, columns
        assert rows["clean.example"]["kvm_detected"] == "no"
        assert rows["noip.example"]["domain"] == "noip.example"

    def test_existing_columns_are_not_duplicated(self, tmp_path):
        import csv
        from enrich_rmm_exposure import annotate_csv

        src = self._domains(tmp_path)
        out = str(tmp_path / "out.csv")
        annotate_csv(src, out, {}, ip_column="a_record")
        annotate_csv(out, out, {}, ip_column="a_record")

        header = next(csv.reader(open(out, encoding="utf-8")))
        assert header.count("kvm_detected") == 1, header


class TestFaviconSweepQueries:
    """The ASN sweep searched only http.title, while host lookups also matched
    favicon hashes. A retitled device inside a swept ASN was therefore invisible
    to the sweep but would have been caught by a direct lookup -- an asymmetry
    worth closing, since retitling is trivial and replacing the favicon is not.
    """

    def test_favicon_query_is_built(self):
        from enrich_rmm_exposure import kvm_favicon_queries
        qs = kvm_favicon_queries()
        assert qs, "expected at least one favicon query"
        for q in qs:
            assert q.startswith("http.favicon.hash:"), q
            assert " OR " not in q and "(" not in q

    def test_covers_every_known_favicon(self):
        from enrich_rmm_exposure import kvm_favicon_queries, KVM_SIGNATURES
        known = {h for s in KVM_SIGNATURES.values() for h in s.get("favicons", [])}
        joined = " ".join(kvm_favicon_queries())
        for h in known:
            assert str(h) in joined, f"favicon {h} not covered by sweep"

    def test_sweep_queries_combine_title_and_favicon(self):
        from enrich_rmm_exposure import asn_sweep_queries
        qs = asn_sweep_queries("AS29802")
        assert all(q.startswith("asn:AS29802 ") for q in qs), qs
        assert any("http.title:" in q for q in qs)
        assert any("http.favicon.hash:" in q for q in qs)


class TestMeshCentral:
    """Found by passive DNS on 23.227.173.144: a mesh.<domain> hostname
    alongside rust.<domain>, i.e. MeshCentral running next to RustDesk.
    MeshCentral is a self-hosted RMM and was missing from the signatures.
    """

    def test_meshcentral_by_title(self):
        r = classify_host(host(svc(443, title="MeshCentral")))
        assert r["rmm_detected"] is True
        assert "MeshCentral" in r["rmm_products"]

    def test_meshcentral_by_product(self):
        r = classify_host(host(svc(8086, product="MeshCentral")))
        assert r["rmm_detected"] is True


class TestDomainCsvSourcing:
    """FP-0011 matches domain rows, so the IPs worth checking are the ones
    those rows resolve to. dea_domains_probed.csv holds 330k rows resolving to
    ~31.7k unique IPs -- roughly 8.8h at Shodan's ~1 req/s, so runs must be
    budgeted and incremental rather than exhaustive.
    """

    def _csv(self, tmp_path, rows):
        import csv
        p = tmp_path / "domains.csv"
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["domain", "a_record", "priority"])
            w.writeheader()
            for r in rows:
                w.writerow(r)
        return str(p)

    def test_extracts_unique_valid_ips(self, tmp_path):
        from enrich_rmm_exposure import load_ips_from_csv
        src = self._csv(tmp_path, [
            {"domain": "a.example", "a_record": "203.0.113.1", "priority": "high"},
            {"domain": "b.example", "a_record": "203.0.113.2", "priority": "low"},
            {"domain": "c.example", "a_record": "203.0.113.1", "priority": "high"},
            {"domain": "d.example", "a_record": "", "priority": "low"},
            {"domain": "e.example", "a_record": "not-an-ip", "priority": "low"},
        ])
        ips = load_ips_from_csv(src, "a_record")
        assert ips == ["203.0.113.1", "203.0.113.2"]

    def test_missing_file_returns_empty(self, tmp_path):
        from enrich_rmm_exposure import load_ips_from_csv
        assert load_ips_from_csv(str(tmp_path / "nope.csv"), "a_record") == []

    def test_missing_column_returns_empty_not_error(self, tmp_path):
        from enrich_rmm_exposure import load_ips_from_csv
        src = self._csv(tmp_path, [{"domain": "a.example", "a_record": "203.0.113.1", "priority": "x"}])
        assert load_ips_from_csv(src, "no_such_column") == []
