#!/usr/bin/env python3
"""Regression tests for the Seads Ad Scan wall-clock budget (issue #50).

Incident: the Daily Data Update discovery job died at the workflow step's
``timeout-minutes: 20`` while run_seads.py was on keyword 25/30, skipping every
later discovery step. Worst-case runtime (30 keywords x 120s subprocess
timeout) never fit the step budget; slow ad-engine days pushed real runtime
past it.

Contract under test: scan_keywords() stops starting new keywords once the
remaining budget cannot cover one worst-case keyword, logs exactly which
keywords were skipped, and returns cleanly so the workflow step exits 0 with
partial results.
"""

import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import run_seads


class FakeClock:
    """Monotonic clock advanced manually by the fake subprocess runner."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


def _install_fakes(monkeypatch, seconds_per_keyword):
    """Replace run_seads' time and subprocess module references (namespace-local,
    no global patching). Returns (clock, calls) where calls collects the keyword
    scanned by each fake subprocess invocation."""
    clock = FakeClock()
    calls = []

    def fake_run(cmd, check=False, timeout=None):
        calls.append(cmd)
        clock.now += seconds_per_keyword
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(run_seads, "time", SimpleNamespace(monotonic=clock.monotonic))
    monkeypatch.setattr(
        run_seads,
        "subprocess",
        SimpleNamespace(run=fake_run, TimeoutExpired=subprocess.TimeoutExpired),
    )
    return clock, calls


def test_stops_cleanly_when_budget_cannot_cover_next_keyword(monkeypatch, tmp_path, caplog):
    monkeypatch.chdir(tmp_path)
    _clock, calls = _install_fakes(monkeypatch, seconds_per_keyword=100)
    keywords = [f"kw{i}" for i in range(10)]

    # budget 500s, per-keyword worst case 120s: after 4 scans elapsed=400,
    # 400+120 > 500, so keyword 5 must not start.
    skipped = run_seads.scan_keywords(keywords, "seads", budget_seconds=500)

    assert len(calls) == 4
    assert skipped == keywords[4:]


def test_logs_skipped_keywords(monkeypatch, tmp_path, caplog):
    monkeypatch.chdir(tmp_path)
    _install_fakes(monkeypatch, seconds_per_keyword=100)
    keywords = [f"kw{i}" for i in range(10)]

    with caplog.at_level("WARNING"):
        run_seads.scan_keywords(keywords, "seads", budget_seconds=500)

    log_text = caplog.text
    assert "4/10" in log_text
    for kw in keywords[4:]:
        assert kw in log_text


def test_no_budget_scans_all_keywords(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _clock, calls = _install_fakes(monkeypatch, seconds_per_keyword=100)
    keywords = [f"kw{i}" for i in range(10)]

    skipped = run_seads.scan_keywords(keywords, "seads", budget_seconds=None)

    assert len(calls) == 10
    assert skipped == []


def test_generous_budget_scans_all_keywords(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _clock, calls = _install_fakes(monkeypatch, seconds_per_keyword=10)
    keywords = [f"kw{i}" for i in range(5)]

    skipped = run_seads.scan_keywords(keywords, "seads", budget_seconds=3600)

    assert len(calls) == 5
    assert skipped == []


def test_main_passes_budget_seconds_to_scan(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    os.makedirs("data")
    captured = {}

    monkeypatch.setattr(run_seads, "install_seads", lambda: "seads")

    def fake_scan(keywords, seads_bin, budget_seconds=None):
        captured["keywords"] = keywords
        captured["budget_seconds"] = budget_seconds
        return []

    monkeypatch.setattr(run_seads, "scan_keywords", fake_scan)
    monkeypatch.setattr(
        sys, "argv", ["run_seads.py", "--keywords", "a,b", "--budget-seconds", "300"]
    )

    run_seads.main()

    assert captured["keywords"] == ["a", "b"]
    assert captured["budget_seconds"] == 300
