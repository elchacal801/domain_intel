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
        """Ports, product banners and titles are all valid matchers. Title
        matching was added for MeshCentral, which has no fixed port; Remotely
        is title-only for the same reason."""
        for name, sig in RMM_SIGNATURES.items():
            assert sig.get("ports") or sig.get("products") or sig.get("titles"),                 f"{name} has no matcher"


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


class TestResultsLedger:
    """The results CSV is the progress ledger, not the SQLite cache.

    The cache expires at 30 days; if progress depended on it, day 31 would
    silently restart the sweep from the top. Recording checked_date per IP and
    skipping recently-checked addresses makes progress survive cache loss.
    """

    def _write(self, path, rows):
        import csv
        from enrich_rmm_exposure import FIELDS
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)

    def test_load_existing_returns_ip_keyed_map(self, tmp_path):
        from enrich_rmm_exposure import load_existing_results
        p = str(tmp_path / "r.csv")
        self._write(p, [
            {"ip": "1.1.1.1", "checked_date": "2026-08-20", "kvm_detected": "False"},
            {"ip": "2.2.2.2", "checked_date": "2026-08-21", "kvm_detected": "True"},
        ])
        got = load_existing_results(p)
        assert set(got) == {"1.1.1.1", "2.2.2.2"}
        assert got["2.2.2.2"]["kvm_detected"] == "True"

    def test_missing_file_is_empty_not_error(self, tmp_path):
        from enrich_rmm_exposure import load_existing_results
        assert load_existing_results(str(tmp_path / "nope.csv")) == {}

    def test_merge_dedupes_by_ip_newest_wins(self):
        from enrich_rmm_exposure import merge_results
        existing = {"1.1.1.1": {"ip": "1.1.1.1", "checked_date": "2026-08-01",
                                "rmm_products": "", "rmm_detected": "False"}}
        new = [{"ip": "1.1.1.1", "checked_date": "2026-08-23",
                "rmm_products": "RustDesk", "rmm_detected": "True"},
               {"ip": "9.9.9.9", "checked_date": "2026-08-23",
                "rmm_products": "", "rmm_detected": "False"}]
        merged = merge_results(existing, new)
        assert len(merged) == 2
        by_ip = {r["ip"]: r for r in merged}
        assert by_ip["1.1.1.1"]["rmm_products"] == "RustDesk", "newer record must win"
        assert by_ip["1.1.1.1"]["checked_date"] == "2026-08-23"

    def test_merge_never_loses_prior_rows(self):
        from enrich_rmm_exposure import merge_results
        existing = {f"10.0.0.{i}": {"ip": f"10.0.0.{i}", "checked_date": "2026-08-01"}
                    for i in range(1, 51)}
        merged = merge_results(existing, [{"ip": "10.0.0.1", "checked_date": "2026-08-23"}])
        assert len(merged) == 50, "appending must not drop untouched rows"

    def test_recently_checked_ips_are_skipped(self):
        from enrich_rmm_exposure import filter_unchecked
        existing = {"1.1.1.1": {"ip": "1.1.1.1", "checked_date": "2026-08-23"},
                    "2.2.2.2": {"ip": "2.2.2.2", "checked_date": "2026-01-01"}}
        todo = filter_unchecked(["1.1.1.1", "2.2.2.2", "3.3.3.3"], existing,
                                today="2026-08-23", max_age_days=30)
        assert todo == ["2.2.2.2", "3.3.3.3"], "fresh skipped, stale and new kept"

    def test_blank_checked_date_is_treated_as_stale(self):
        from enrich_rmm_exposure import filter_unchecked
        existing = {"1.1.1.1": {"ip": "1.1.1.1", "checked_date": ""}}
        assert filter_unchecked(["1.1.1.1"], existing, today="2026-08-23") == ["1.1.1.1"]


class TestRateLimiting:
    """~31.7k lookups at Shodan's ~1 req/s needs pacing and resilience; a
    143-IP test was too small to expose either need."""

    def test_throttle_sleeps_to_maintain_interval(self):
        from unittest.mock import patch
        from enrich_rmm_exposure import Throttle
        slept = []
        with patch("enrich_rmm_exposure.time.sleep", side_effect=slept.append):
            with patch("enrich_rmm_exposure.time.monotonic", side_effect=[100.0, 100.2, 100.2]):
                t = Throttle(min_interval=1.0)
                t.wait()   # first call: no wait
                t.wait()   # 0.2s later: must sleep ~0.8s
        assert slept and 0.7 < slept[0] <= 1.0, slept

    def test_lookup_retries_then_succeeds(self):
        from unittest.mock import MagicMock, patch
        from enrich_rmm_exposure import lookup_host
        api = MagicMock()
        api.host.side_effect = [Exception("rate limit"), {"ip_str": "1.2.3.4", "data": []}]
        with patch("enrich_rmm_exposure.time.sleep"):
            rec, used = lookup_host(api, "1.2.3.4", cache=None, retries=2)
        assert rec is not None and used is True
        assert api.host.call_count == 2

    def test_unknown_ip_is_not_retried(self):
        from unittest.mock import MagicMock, patch
        from enrich_rmm_exposure import lookup_host
        api = MagicMock()
        api.host.side_effect = Exception("No information available for that IP.")
        with patch("enrich_rmm_exposure.time.sleep"):
            rec, used = lookup_host(api, "1.2.3.4", cache=None, retries=3)
        assert rec is None
        assert api.host.call_count == 1, "a genuine 'not found' must not burn retries"


class TestMultipleSources:
    """Both the domain set and the VPN relay set are swept, and they key their
    IPs in differently-named columns (a_record vs ip)."""

    def test_parses_path_and_column(self):
        from enrich_rmm_exposure import parse_source
        assert parse_source("data/x.csv:ip") == ("data/x.csv", "ip")

    def test_defaults_column_when_omitted(self):
        from enrich_rmm_exposure import parse_source
        assert parse_source("data/x.csv") == ("data/x.csv", "a_record")

    def test_windows_drive_letter_is_not_split(self):
        from enrich_rmm_exposure import parse_source
        assert parse_source(r"C:\data\x.csv:ip") == (r"C:\data\x.csv", "ip")
        assert parse_source(r"C:\data\x.csv") == (r"C:\data\x.csv", "a_record")


class TestLaptopFarmArtifacts:
    """Indicators from mattysplo.it's laptop-farm write-up (2025-06-13)."""

    def test_screenconnect_by_port(self):
        r = classify_host(host(svc(8172)))
        assert r["rmm_detected"] is True
        assert "ScreenConnect" in r["rmm_products"]

    def test_screenconnect_by_product_banner(self):
        r = classify_host(host(svc(443, product="ScreenConnect")))
        assert "ScreenConnect" in r["rmm_products"]

    def test_connectwise_control_by_title(self):
        r = classify_host(host(svc(443, title="ConnectWise Control")))
        assert "ScreenConnect" in r["rmm_products"]

    @pytest.mark.parametrize("port", [5900, 5901, 5902, 5903, 5904, 5905])
    def test_full_vnc_display_range(self, port):
        """Farms were documented using the whole 5900-5905 range, not just :0/:1."""
        r = classify_host(host(svc(port)))
        assert r["rmm_detected"] is True
        assert "VNC" in r["rmm_products"]

    def test_port_5906_is_not_claimed_as_vnc(self):
        r = classify_host(host(svc(5906)))
        assert "VNC" not in r["rmm_products"]


class TestHardwareIdentifiers:
    """Host-side identifiers this pipeline cannot query, recorded for the
    LogScale/EDR side (ARP tables, USB enumeration)."""

    def test_reference_file_is_wellformed(self):
        import csv, io, os
        p = os.path.join(os.path.dirname(__file__), "..", "data",
                         "kvm_hardware_identifiers.csv")
        rows = list(csv.DictReader(io.open(p, encoding="utf-8", newline="")))
        assert len(rows) >= 15
        for r in rows:
            assert r["product"] and r["identifier_type"] and r["value"]
            assert r["source"], "every identifier must cite its source"

    def test_covers_both_kvm_products_and_key_types(self):
        import csv, io, os
        p = os.path.join(os.path.dirname(__file__), "..", "data",
                         "kvm_hardware_identifiers.csv")
        rows = list(csv.DictReader(io.open(p, encoding="utf-8", newline="")))
        assert {"PiKVM", "TinyPilot"} <= {r["product"] for r in rows}
        assert {"mac_prefix", "usb_vendor_id", "usb_serial"} <= {r["identifier_type"] for r in rows}


class TestAdditionalRMMProducts:
    """Products present in C2IntelFeeds' RMM feed that we did not detect.

    Their 90-day feed carries 61,115 RMM IPs across nine products; we covered
    only ScreenConnect and MeshCentral of those. Signature volumes below were
    measured against live Shodan before adoption.
    """

    def test_splashtop_by_port(self):
        """Default ports 6783-6785 (374 hosts on 6783)."""
        for port in (6783, 6784, 6785):
            r = classify_host(host(svc(port)))
            assert "Splashtop" in r["rmm_products"], port

    def test_splashtop_by_title(self):
        assert "Splashtop" in classify_host(host(svc(443, title="Splashtop Gateway")))["rmm_products"]

    def test_simplehelp_by_title(self):
        assert "SimpleHelp" in classify_host(host(svc(443, title="SimpleHelp")))["rmm_products"]

    def test_tactical_rmm_by_title(self):
        assert "Tactical RMM" in classify_host(host(svc(443, title="Tactical RMM")))["rmm_products"]

    def test_komari_by_title(self):
        assert "Komari" in classify_host(host(svc(443, title="Komari Monitor")))["rmm_products"]

    def test_nable_by_title(self):
        assert "N-able" in classify_host(host(svc(443, title="N-able N-central")))["rmm_products"]

    def test_kaseya_by_title(self):
        assert "Kaseya" in classify_host(host(svc(443, title="Kaseya VSA")))["rmm_products"]

    def test_remotely_by_title(self):
        assert "Remotely" in classify_host(host(svc(443, title="Remotely")))["rmm_products"]

    def test_ordinary_page_mentioning_remotely_is_not_matched(self):
        """'remotely' is an ordinary English word: http.html:"remotely" matches
        14,611 hosts against 425 for the title. Body matching would be noise,
        so Remotely is title-only and must not fire on prose."""
        r = classify_host(host(svc(80, product="nginx",
                                   title="Work From Home - Access Your PC")))
        assert "Remotely" not in r["rmm_products"]

    def test_all_new_products_are_in_the_table(self):
        for p in ("Splashtop", "SimpleHelp", "Tactical RMM", "Komari",
                  "N-able", "Kaseya", "Remotely"):
            assert p in RMM_SIGNATURES, f"{p} missing from RMM_SIGNATURES"


class TestGzippedSources:
    """data/dea_domains_probed.csv is gitignored and only the .csv.gz is
    committed, so a fresh clone has no plain CSV. Without transparent gzip
    reading, --source silently loads zero IPs from it and the sweep quietly
    covers two of three sources -- a missing 31,700 addresses."""

    def _write_gz(self, path, rows):
        import gzip, csv, io
        with gzip.open(path, "wt", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["domain", "a_record"])
            w.writeheader()
            for r in rows:
                w.writerow(r)

    def test_reads_gz_when_plain_csv_absent(self, tmp_path):
        from enrich_rmm_exposure import load_ips_from_csv
        gz = tmp_path / "probed.csv.gz"
        self._write_gz(gz, [{"domain": "a.example", "a_record": "203.0.113.1"},
                            {"domain": "b.example", "a_record": "203.0.113.2"}])
        # caller asks for the plain path, which does not exist
        assert load_ips_from_csv(str(tmp_path / "probed.csv"), "a_record") == \
            ["203.0.113.1", "203.0.113.2"]

    def test_plain_csv_wins_when_both_exist(self, tmp_path):
        import csv, io
        from enrich_rmm_exposure import load_ips_from_csv
        plain = tmp_path / "probed.csv"
        with io.open(plain, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["domain", "a_record"])
            w.writeheader(); w.writerow({"domain": "x", "a_record": "198.51.100.9"})
        self._write_gz(tmp_path / "probed.csv.gz",
                       [{"domain": "stale", "a_record": "203.0.113.99"}])
        assert load_ips_from_csv(str(plain), "a_record") == ["198.51.100.9"], \
            "the freshly written plain file must take precedence over the archive"

    def test_neither_present_is_still_empty_not_error(self, tmp_path):
        from enrich_rmm_exposure import load_ips_from_csv
        assert load_ips_from_csv(str(tmp_path / "nope.csv"), "a_record") == []


class TestLedgerBooleanRoundTrip:
    """classify_host returns real booleans, but the ledger round-trips them
    through CSV as the strings 'True'/'False'. bool('False') is True, so
    annotate_csv marked every annotated domain as exposed: 40,218 domains
    carried kvm_detected=yes against a ledger holding 114 real exposures.
    """

    def _domains(self, tmp_path):
        import csv
        p = tmp_path / "domains.csv"
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["domain", "a_record"])
            w.writeheader()
            w.writerow({"domain": "clean.example", "a_record": "203.0.113.1"})
            w.writerow({"domain": "hit.example", "a_record": "203.0.113.2"})
        return str(p)

    def test_string_false_from_the_ledger_is_not_treated_as_true(self, tmp_path):
        import csv
        from enrich_rmm_exposure import annotate_csv
        src = self._domains(tmp_path)
        out = str(tmp_path / "out.csv")
        # exactly what load_existing_results returns after a CSV round-trip
        findings = {
            "203.0.113.1": {"ip": "203.0.113.1", "kvm_detected": "False",
                            "rmm_detected": "False", "kvm_products": "",
                            "rmm_products": "", "exposure_evidence": ""},
            "203.0.113.2": {"ip": "203.0.113.2", "kvm_detected": "True",
                            "rmm_detected": "False", "kvm_products": "PiKVM",
                            "rmm_products": "", "exposure_evidence": "443:PiKVM(title)"},
        }
        n = annotate_csv(src, out, findings, ip_column="a_record")
        rows = {r["domain"]: r for r in csv.DictReader(open(out, encoding="utf-8"))}
        assert rows["clean.example"]["kvm_detected"] == "no", \
            "the string 'False' must not annotate as exposed"
        assert rows["hit.example"]["kvm_detected"] == "yes"
        assert n == 1, "only genuinely exposed rows count as annotated"

    def test_real_booleans_still_work(self, tmp_path):
        import csv
        from enrich_rmm_exposure import annotate_csv
        src = self._domains(tmp_path)
        out = str(tmp_path / "out.csv")
        findings = {"203.0.113.2": {"ip": "203.0.113.2", "kvm_detected": True,
                                    "rmm_detected": False, "kvm_products": "PiKVM",
                                    "rmm_products": "", "exposure_evidence": "x"}}
        annotate_csv(src, out, findings, ip_column="a_record")
        rows = {r["domain"]: r for r in csv.DictReader(open(out, encoding="utf-8"))}
        assert rows["hit.example"]["kvm_detected"] == "yes"
        assert rows["hit.example"]["rmm_detected"] == "no"

    def test_hit_counting_survives_the_round_trip(self):
        from enrich_rmm_exposure import is_true
        assert is_true(True) and is_true("True") and is_true("true") and is_true("yes")
        assert not is_true(False) and not is_true("False") and not is_true("false")
        assert not is_true("") and not is_true(None) and not is_true("no")
