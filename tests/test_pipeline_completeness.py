#!/usr/bin/env python3
"""Regression tests for the silent domain-drop bug in the shard pipeline.

Incident: dea_domains_probed.csv was missing contiguous alphabetical bands of
input domains, different bands each run. Root cause: enrich_infrastructure.py's
--timeout-minutes deadline broke out of the result-collection loop and wrote
only completed rows, silently dropping the unprocessed tail of each shard.

Contract under test: every input domain produces exactly one output row; rows
that could not be enriched carry a populated ``error`` column; each stage
reconciles its output domain set against its input and fails loudly on
mismatch.
"""

import asyncio
import csv
import os
import sys
import time
from types import SimpleNamespace

import dns.asyncresolver
import dns.exception
import dns.resolver
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import enrich_infrastructure as ei
import enrich_reputation as rep
import merge_results
import probe_web


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_domains_csv(path, domains, extra_cols=None):
    extra_cols = extra_cols or {}
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["domain"] + list(extra_cols))
        for d in domains:
            writer.writerow([d] + [extra_cols[c] for c in extra_cols])


def _read_rows(path):
    with open(path, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _fake_answer(rdtype):
    """Minimal fake dnspython answer objects for each rdtype the code parses."""
    if rdtype == "NS":
        return [SimpleNamespace(target="ns1.ok.example.")]
    if rdtype == "MX":
        return [SimpleNamespace(preference=10, exchange="mx.ok.example.")]
    if rdtype == "A":
        return [SimpleNamespace(to_text=lambda: "203.0.113.7")]
    if rdtype == "TXT":
        return [SimpleNamespace(to_text=lambda: '"13335 | 203.0.113.0/24 | US | arin"')]
    return []


# ---------------------------------------------------------------------------
# enrich_infrastructure: deadline must not drop domains (the incident)
# ---------------------------------------------------------------------------

class TestDeadlineCompleteness:
    def test_deadline_truncation_writes_row_for_every_domain(self, tmp_path, monkeypatch):
        """When the global deadline fires mid-run, unprocessed domains must
        still be written as rows with a populated error column, not dropped.

        Mirrors the incident: input sorted, a contiguous tail is slow, the
        deadline cuts processing partway through.
        """
        domains = [f"{p}{i:02d}.example" for p in ("aa", "bb", "cc", "dd") for i in range(10)]
        slow = set(domains[20:])  # contiguous tail, like a shard tail

        inp = tmp_path / "in.csv"
        out = tmp_path / "out.csv"
        _write_domains_csv(inp, domains)

        class FakeResolver:
            def __init__(self, nameservers=None):
                pass

            async def resolve_ns(self, domain):
                if domain in slow:
                    await asyncio.sleep(2.5)
                return ["ns1.fast.example"]

            async def resolve_a(self, hostname):
                return ""

            async def resolve_mx(self, domain):
                return []

        monkeypatch.setattr(ei, "AsyncResolver", FakeResolver)
        monkeypatch.setattr(ei, "_DEADLINE", time.time() + 1.0)

        asyncio.run(ei.runner(str(inp), str(out), concurrency=5))

        rows = _read_rows(out)
        out_domains = [r["domain"] for r in rows]

        # The actual deliverable: no input domain may vanish.
        assert len(out_domains) == len(domains), (
            f"{len(domains) - len(out_domains)} domains dropped from output"
        )
        assert set(out_domains) == set(domains)

        # Unenriched rows must say why.
        for r in rows:
            enriched = bool(r["nameservers"])
            assert enriched or r["error"], f"{r['domain']} has no data and no error"

        deadline_rows = [r for r in rows if r["error"] == "deadline_exceeded"]
        assert len(deadline_rows) >= 10, "expected the unprocessed tail to be marked"

    def test_reconcile_or_die_fails_loudly_on_mismatch(self, capsys):
        inputs = {"a.example", "b.example", "c.example", "d.example"}
        outputs = {"a.example"}

        with pytest.raises(SystemExit) as excinfo:
            ei.reconcile_or_die(inputs, outputs)
        assert excinfo.value.code == 1

        printed = capsys.readouterr().out
        assert "3" in printed  # missing count
        assert "b.example" in printed  # sample of missing domains

        # Equal sets must not raise.
        ei.reconcile_or_die(inputs, set(inputs))


# ---------------------------------------------------------------------------
# enrich_infrastructure: transient failures retried then recorded, permanent
# failures recorded without retry (DNS layer mocked, contiguous slice raises)
# ---------------------------------------------------------------------------

class TestFailureClassification:
    def _run_with_dns(self, tmp_path, monkeypatch, domains, side_effect):
        """Run runner() with the real AsyncResolver but the dnspython layer
        mocked. side_effect(qname, rdtype) returns answers or raises."""
        calls = {}

        async def fake_resolve(self_resolver, qname, rdtype, *args, **kwargs):
            key = (str(qname).rstrip("."), rdtype)
            calls[key] = calls.get(key, 0) + 1
            return side_effect(str(qname).rstrip("."), rdtype)

        monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)
        monkeypatch.setattr(ei, "RETRY_BACKOFF_BASE", 0.01, raising=False)
        monkeypatch.setattr(ei, "_DEADLINE", None)

        inp = tmp_path / "in.csv"
        out = tmp_path / "out.csv"
        _write_domains_csv(inp, domains)
        asyncio.run(ei.runner(str(inp), str(out), concurrency=10))
        return _read_rows(out), calls

    def test_transient_dns_slice_is_retried_and_recorded(self, tmp_path, monkeypatch):
        """A contiguous slice of the input times out on every DNS query.
        Every domain must still appear in the output; the failing slice must
        carry a transient error after retry exhaustion."""
        domains = [f"{p}{i:02d}.example" for p in ("fa", "fb", "fc") for i in range(10)]
        failing = set(domains[10:20])  # the whole 'fb' prefix

        def side_effect(qname, rdtype):
            if qname in failing:
                raise dns.exception.Timeout()
            return _fake_answer(rdtype)

        rows, calls = self._run_with_dns(tmp_path, monkeypatch, domains, side_effect)

        assert {r["domain"] for r in rows} == set(domains)
        assert len(rows) == len(domains)

        for r in rows:
            if r["domain"] in failing:
                assert r["error"].startswith("transient:"), (
                    f"{r['domain']} should record a transient error, got {r['error']!r}"
                )
            else:
                assert r["error"] == ""
                assert r["nameservers"] == "ns1.ok.example"

        # Transient failures must be retried with backoff before giving up.
        assert calls[("fb00.example", "NS")] >= 2, "expected a retry on timeout"
        assert calls[("fa00.example", "NS")] == 1

    def test_nxdomain_is_permanent_and_not_retried(self, tmp_path, monkeypatch):
        domains = [f"{p}{i:02d}.example" for p in ("ga", "gb") for i in range(5)]
        dead = set(domains[5:])  # the whole 'gb' prefix

        def side_effect(qname, rdtype):
            if qname in dead:
                raise dns.resolver.NXDOMAIN()
            return _fake_answer(rdtype)

        rows, calls = self._run_with_dns(tmp_path, monkeypatch, domains, side_effect)

        assert {r["domain"] for r in rows} == set(domains)
        for r in rows:
            if r["domain"] in dead:
                assert r["error"] == "NXDOMAIN"
            else:
                assert r["error"] == ""

        assert calls[("gb00.example", "NS")] == 1, "NXDOMAIN must not be retried"


# ---------------------------------------------------------------------------
# merge_results: end-of-run reconciliation against the pipeline input
# ---------------------------------------------------------------------------

class TestMergeReconciliation:
    def _write_shard(self, path, domains):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["domain", "primary_mx", "error"])
            for d in domains:
                writer.writerow([d, "", ""])

    def test_missing_domains_fail_the_merge(self, tmp_path, monkeypatch, capsys):
        self._write_shard(tmp_path / "result_part_0.csv", ["a.example", "b.example"])
        self._write_shard(tmp_path / "result_part_1.csv", ["c.example", "d.example"])
        expect = tmp_path / "input.csv"
        _write_domains_csv(expect, ["a.example", "b.example", "c.example", "d.example", "e.example"])

        out = tmp_path / "merged.csv"
        monkeypatch.setattr(sys, "argv", [
            "merge_results.py",
            "--pattern", str(tmp_path / "result_part_*.csv"),
            "--output", str(out),
            "--expect-input", str(expect),
        ])
        with pytest.raises(SystemExit) as excinfo:
            merge_results.main()
        assert excinfo.value.code == 1

        printed = capsys.readouterr().out
        assert "e.example" in printed
        assert "1" in printed

    def test_complete_merge_passes_reconciliation(self, tmp_path, monkeypatch):
        self._write_shard(tmp_path / "result_part_0.csv", ["a.example", "b.example"])
        self._write_shard(tmp_path / "result_part_1.csv", ["c.example", "d.example"])
        expect = tmp_path / "input.csv"
        _write_domains_csv(expect, ["a.example", "b.example", "c.example", "d.example"])

        out = tmp_path / "merged.csv"
        monkeypatch.setattr(sys, "argv", [
            "merge_results.py",
            "--pattern", str(tmp_path / "result_part_*.csv"),
            "--output", str(out),
            "--expect-input", str(expect),
        ])
        merge_results.main()  # must not raise

        rows = _read_rows(out)
        assert {r["domain"] for r in rows} == {"a.example", "b.example", "c.example", "d.example"}


# ---------------------------------------------------------------------------
# enrich_reputation: deadline pass-through must be annotated, never dropped
# ---------------------------------------------------------------------------

class TestReputationPassThrough:
    def test_deadline_passthrough_keeps_and_annotates_rows(self, tmp_path, monkeypatch):
        domains = [f"r{i:02d}.example" for i in range(20)]
        inp = tmp_path / "in.csv"
        out = tmp_path / "out.csv"
        _write_domains_csv(inp, domains, extra_cols={"error": ""})

        monkeypatch.setattr(rep, "_DEADLINE", time.time() - 1)  # already expired
        monkeypatch.setattr(sys, "argv", [
            "enrich_reputation.py",
            "--input", str(inp),
            "--output", str(out),
            "--workers", "4",
        ])
        rep.main()

        rows = _read_rows(out)
        assert [r["domain"] for r in rows] == domains, "pass-through must not drop rows"
        for r in rows:
            assert "reputation:deadline_exceeded" in r["error"]
        # The marker must not be applied twice to the same row.
        assert all(r["error"].count("reputation:deadline_exceeded") == 1 for r in rows)


# ---------------------------------------------------------------------------
# probe_web: per-domain timeouts and unattempted rows must be annotated
# ---------------------------------------------------------------------------

class TestProbeAnnotations:
    def test_worker_annotates_timeout_and_marks_processed(self, monkeypatch):
        async def run():
            row = {"domain": "slow.example", "error": ""}
            queue = asyncio.Queue()
            queue.put_nowait(row)
            processed_ids = set()

            async def fake_wait_for(coro, timeout):
                coro.close()
                raise asyncio.TimeoutError()

            monkeypatch.setattr(probe_web.asyncio, "wait_for", fake_wait_for)

            task = asyncio.create_task(
                probe_web.worker(queue, None, None, processed_ids)
            )
            await queue.join()
            task.cancel()

            assert "probe:timeout" in row["error"]
            assert id(row) in processed_ids

        asyncio.run(run())
