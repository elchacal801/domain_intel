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
