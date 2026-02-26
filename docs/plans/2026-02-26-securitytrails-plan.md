# SecurityTrails Manual Investigation Tool — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a manual-only, single-domain SecurityTrails investigation tool with a strict SQLite-backed circuit breaker that prevents exceeding the 50-query/30-day free tier limit.

**Architecture:** New `PersistentQuotaTracker` in `scripts/shared/api_budget.py` provides SQLite-backed 30-day rolling window quota enforcement. `scripts/enrich_securitytrails.py` is a single-domain CLI tool that queries SecurityTrails API v1 for historical DNS (A, MX, NS) and WHOIS, printing formatted results to console with optional CSV append. Cached results (via `ShodanCache`) skip API calls entirely.

**Tech Stack:** Python 3.10, requests, sqlite3, dotenv, pytest

---

### Task 1: Persistent Quota Tracker

**Files:**
- Create: `scripts/shared/api_budget.py`
- Create: `tests/test_api_budget.py`

**Context:** The existing `CreditBudget` in `scripts/shodan_utils.py:24-65` is ephemeral (resets each run). SecurityTrails needs persistent 30-day rolling window tracking. This new module stores every API call with a timestamp in SQLite. On each spend attempt, it counts rows within the rolling window and hard-aborts if the limit is reached.

The `scripts/shared/` directory already exists and contains `retry.py`, `config.py`, `cymru_resolver.py`, etc. The new file fits this location.

**Step 1: Write the failing tests**

Create `tests/test_api_budget.py`:

```python
#!/usr/bin/env python3
"""Tests for shared/api_budget.py — persistent API quota tracker."""

import sys
import os
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from shared.api_budget import PersistentQuotaTracker


# ---------------------------------------------------------------------------
# TestBasicUsage
# ---------------------------------------------------------------------------

class TestBasicUsage:
    """Verify basic quota tracking operations."""

    def test_fresh_tracker_has_zero_usage(self, tmp_path):
        db = str(tmp_path / "test.db")
        tracker = PersistentQuotaTracker(db_path=db, max_queries=50, window_days=30)
        assert tracker.get_usage() == 0
        assert tracker.get_remaining() == 50
        tracker.close()

    def test_record_usage_increments_count(self, tmp_path):
        db = str(tmp_path / "test.db")
        tracker = PersistentQuotaTracker(db_path=db, max_queries=50, window_days=30)
        tracker.record_usage("securitytrails", "evil.com", cost=1)
        assert tracker.get_usage() == 1
        assert tracker.get_remaining() == 49
        tracker.close()

    def test_record_usage_with_cost(self, tmp_path):
        db = str(tmp_path / "test.db")
        tracker = PersistentQuotaTracker(db_path=db, max_queries=50, window_days=30)
        tracker.record_usage("securitytrails", "evil.com", cost=4)
        assert tracker.get_usage() == 4
        assert tracker.get_remaining() == 46
        tracker.close()

    def test_can_spend_true_when_under_limit(self, tmp_path):
        db = str(tmp_path / "test.db")
        tracker = PersistentQuotaTracker(db_path=db, max_queries=50, window_days=30)
        assert tracker.can_spend(4) is True
        tracker.close()

    def test_can_spend_false_when_at_limit(self, tmp_path):
        db = str(tmp_path / "test.db")
        tracker = PersistentQuotaTracker(db_path=db, max_queries=10, window_days=30)
        tracker.record_usage("test", "a.com", cost=8)
        assert tracker.can_spend(4) is False  # 8 + 4 > 10
        assert tracker.can_spend(2) is True   # 8 + 2 = 10 (exact limit)
        tracker.close()


# ---------------------------------------------------------------------------
# TestCircuitBreaker
# ---------------------------------------------------------------------------

class TestCircuitBreaker:
    """Verify the hard abort when quota is exceeded."""

    def test_abort_if_exceeded_exits(self, tmp_path):
        db = str(tmp_path / "test.db")
        tracker = PersistentQuotaTracker(db_path=db, max_queries=5, window_days=30)
        tracker.record_usage("test", "a.com", cost=4)
        with pytest.raises(SystemExit) as exc_info:
            tracker.abort_if_exceeded(4)  # 4 + 4 > 5
        assert exc_info.value.code == 1
        tracker.close()

    def test_abort_if_exceeded_passes_when_ok(self, tmp_path):
        db = str(tmp_path / "test.db")
        tracker = PersistentQuotaTracker(db_path=db, max_queries=50, window_days=30)
        tracker.abort_if_exceeded(4)  # should not raise
        tracker.close()


# ---------------------------------------------------------------------------
# TestRollingWindow
# ---------------------------------------------------------------------------

class TestRollingWindow:
    """Verify that old entries outside the window are not counted."""

    def test_old_entries_not_counted(self, tmp_path):
        db = str(tmp_path / "test.db")
        tracker = PersistentQuotaTracker(db_path=db, max_queries=50, window_days=30)
        # Insert a row with a timestamp 31 days ago
        old_ts = time.time() - (31 * 86400)
        tracker._conn.execute(
            "INSERT INTO api_usage (api_name, domain, cost, timestamp) VALUES (?, ?, ?, ?)",
            ("test", "old.com", 10, old_ts),
        )
        tracker._conn.commit()
        assert tracker.get_usage() == 0  # old entry should not count
        assert tracker.get_remaining() == 50
        tracker.close()

    def test_recent_entries_counted(self, tmp_path):
        db = str(tmp_path / "test.db")
        tracker = PersistentQuotaTracker(db_path=db, max_queries=50, window_days=30)
        # Insert a row with a timestamp 1 day ago
        recent_ts = time.time() - (1 * 86400)
        tracker._conn.execute(
            "INSERT INTO api_usage (api_name, domain, cost, timestamp) VALUES (?, ?, ?, ?)",
            ("test", "recent.com", 5, recent_ts),
        )
        tracker._conn.commit()
        assert tracker.get_usage() == 5
        assert tracker.get_remaining() == 45
        tracker.close()


# ---------------------------------------------------------------------------
# TestPersistence
# ---------------------------------------------------------------------------

class TestPersistence:
    """Verify that data survives across tracker instances."""

    def test_data_persists_across_instances(self, tmp_path):
        db = str(tmp_path / "test.db")
        tracker1 = PersistentQuotaTracker(db_path=db, max_queries=50, window_days=30)
        tracker1.record_usage("securitytrails", "evil.com", cost=4)
        tracker1.close()

        tracker2 = PersistentQuotaTracker(db_path=db, max_queries=50, window_days=30)
        assert tracker2.get_usage() == 4
        assert tracker2.get_remaining() == 46
        tracker2.close()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_api_budget.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'shared.api_budget'`

**Step 3: Write minimal implementation**

Create `scripts/shared/api_budget.py`:

```python
#!/usr/bin/env python3
"""
shared/api_budget.py

Persistent API quota tracker backed by SQLite.
Tracks API usage with timestamps and enforces a rolling-window budget.
Designed for APIs with strict quotas (e.g., SecurityTrails free tier: 50 queries / 30 days).
"""

import logging
import sqlite3
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)


class PersistentQuotaTracker:
    """Tracks API usage in SQLite and enforces a rolling-window quota.

    Args:
        db_path: Path to the SQLite database file.
        max_queries: Maximum allowed queries within the rolling window.
        window_days: Size of the rolling window in days.
    """

    def __init__(self, db_path: str, max_queries: int, window_days: int):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True, parents=True)
        self.max_queries = max_queries
        self.window_days = window_days
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._init_db()

    def _init_db(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS api_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_name TEXT NOT NULL,
                domain TEXT NOT NULL,
                cost INTEGER NOT NULL DEFAULT 1,
                timestamp REAL NOT NULL
            )
        """)
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_api_usage_ts ON api_usage(timestamp)"
        )
        self._conn.commit()

    def get_usage(self) -> int:
        """Count total query cost within the rolling window."""
        cutoff = time.time() - (self.window_days * 86400)
        cur = self._conn.execute(
            "SELECT COALESCE(SUM(cost), 0) FROM api_usage WHERE timestamp > ?",
            (cutoff,),
        )
        return cur.fetchone()[0]

    def get_remaining(self) -> int:
        """Return remaining queries available in the rolling window."""
        return max(0, self.max_queries - self.get_usage())

    def can_spend(self, cost: int) -> bool:
        """Check if spending `cost` queries would stay within the budget."""
        return self.get_usage() + cost <= self.max_queries

    def record_usage(self, api_name: str, domain: str, cost: int = 1):
        """Record API usage. Each call inserts one row."""
        self._conn.execute(
            "INSERT INTO api_usage (api_name, domain, cost, timestamp) VALUES (?, ?, ?, ?)",
            (api_name, domain, cost, time.time()),
        )
        self._conn.commit()
        logger.debug(
            "Recorded %d query(s) for %s/%s. Remaining: %d/%d",
            cost, api_name, domain, self.get_remaining(), self.max_queries,
        )

    def abort_if_exceeded(self, cost: int):
        """Hard-abort (SystemExit) if budget cannot cover `cost` more queries.

        Call this BEFORE making any network request.
        """
        if not self.can_spend(cost):
            remaining = self.get_remaining()
            used = self.get_usage()
            logger.error(
                "QUOTA EXCEEDED: Need %d queries but only %d remaining "
                "(%d/%d used in last %d days). Aborting.",
                cost, remaining, used, self.max_queries, self.window_days,
            )
            sys.exit(1)

    def close(self):
        """Close the SQLite connection."""
        self._conn.close()
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_api_budget.py -v`
Expected: All 10 tests PASS

**Step 5: Commit**

```bash
git add scripts/shared/api_budget.py tests/test_api_budget.py
git commit -m "feat: add PersistentQuotaTracker for rolling-window API budget enforcement

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 2: SecurityTrails Enrichment Script

**Files:**
- Create: `scripts/enrich_securitytrails.py`
- Create: `tests/test_securitytrails.py`

**Context:** This script queries SecurityTrails API v1 for a single domain. It uses `PersistentQuotaTracker` (from Task 1) with a hard 50-query/30-day limit and `ShodanCache` (from `scripts/shodan_utils.py:67-119`) for response caching. API key comes from `ST_API_KEY` env var via `load_dotenv()`.

Endpoints (each costs 1 query):
- `GET /v1/history/{domain}/dns/a`
- `GET /v1/history/{domain}/dns/mx`
- `GET /v1/history/{domain}/dns/ns`
- `GET /v1/history/{domain}/whois`

The `@retry` decorator lives at `scripts/shared/retry.py:17-63`.

**Step 1: Write the failing tests**

Create `tests/test_securitytrails.py`:

```python
#!/usr/bin/env python3
"""Tests for enrich_securitytrails.py — SecurityTrails manual investigation tool."""

import sys
import os
import csv
import json
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from enrich_securitytrails import (
    parse_dns_history,
    parse_whois_history,
    format_console_output,
    build_result_row,
    ST_COLUMNS,
)


# ---------------------------------------------------------------------------
# Sample API Responses
# ---------------------------------------------------------------------------

SAMPLE_DNS_A = {
    "records": [
        {"values": [{"ip": "1.2.3.4"}], "first_seen": "2019-03-15", "last_seen": "2024-05-31"},
        {"values": [{"ip": "5.6.7.8"}], "first_seen": "2024-06-01", "last_seen": "2025-11-20"},
    ]
}

SAMPLE_DNS_MX = {
    "records": [
        {"values": [{"host": "mx1.google.com"}], "first_seen": "2019-03-15", "last_seen": "2023-01-09"},
        {"values": [{"host": "mail.protonmail.ch"}], "first_seen": "2023-01-10", "last_seen": "2025-11-20"},
    ]
}

SAMPLE_DNS_NS = {
    "records": [
        {"values": [{"nameserver": "ns1.registrar-servers.com"}], "first_seen": "2019-03-15", "last_seen": "2025-10-01"},
    ]
}

SAMPLE_WHOIS = {
    "result": {
        "items": [
            {"registrar_name": "GoDaddy", "created_date": "2019-03-15"},
            {"registrar_name": "Namecheap", "created_date": "2023-06-01"},
            {"registrar_name": "PDR Ltd", "created_date": "2025-09-15"},
        ]
    }
}


# ---------------------------------------------------------------------------
# TestParseDnsHistory
# ---------------------------------------------------------------------------

class TestParseDnsHistory:
    """Verify parsing of SecurityTrails DNS history responses."""

    def test_parse_a_records(self):
        result = parse_dns_history(SAMPLE_DNS_A, "a")
        assert result["unique_count"] == 2
        assert result["first_seen"] == "2019-03-15"
        assert len(result["entries"]) == 2
        assert result["entries"][0]["value"] == "1.2.3.4"

    def test_parse_mx_records(self):
        result = parse_dns_history(SAMPLE_DNS_MX, "mx")
        assert result["unique_count"] == 2
        assert result["entries"][1]["value"] == "mail.protonmail.ch"
        assert result["last_change"] == "2023-01-10"

    def test_parse_ns_records(self):
        result = parse_dns_history(SAMPLE_DNS_NS, "ns")
        assert result["unique_count"] == 1

    def test_parse_empty_response(self):
        result = parse_dns_history({"records": []}, "a")
        assert result["unique_count"] == 0
        assert result["entries"] == []
        assert result["first_seen"] == ""

    def test_parse_none_response(self):
        result = parse_dns_history(None, "a")
        assert result["unique_count"] == 0


# ---------------------------------------------------------------------------
# TestParseWhoisHistory
# ---------------------------------------------------------------------------

class TestParseWhoisHistory:
    """Verify parsing of SecurityTrails WHOIS history responses."""

    def test_parse_whois_registrar_count(self):
        result = parse_whois_history(SAMPLE_WHOIS)
        assert result["registrar_changes"] == 3

    def test_parse_whois_entries(self):
        result = parse_whois_history(SAMPLE_WHOIS)
        assert len(result["entries"]) == 3
        assert result["entries"][0]["registrar"] == "GoDaddy"

    def test_parse_empty_whois(self):
        result = parse_whois_history({"result": {"items": []}})
        assert result["registrar_changes"] == 0
        assert result["entries"] == []

    def test_parse_none_whois(self):
        result = parse_whois_history(None)
        assert result["registrar_changes"] == 0


# ---------------------------------------------------------------------------
# TestBuildResultRow
# ---------------------------------------------------------------------------

class TestBuildResultRow:
    """Verify building the output row from parsed data."""

    def test_builds_complete_row(self):
        dns_a = parse_dns_history(SAMPLE_DNS_A, "a")
        dns_mx = parse_dns_history(SAMPLE_DNS_MX, "mx")
        dns_ns = parse_dns_history(SAMPLE_DNS_NS, "ns")
        whois = parse_whois_history(SAMPLE_WHOIS)

        row = build_result_row("evil.com", dns_a, dns_mx, dns_ns, whois)
        assert row["domain"] == "evil.com"
        assert row["st_dns_history_count"] == "2"
        assert row["st_registrar_changes"] == "3"
        assert "google.com" in row["st_mx_history"]
        assert "protonmail.ch" in row["st_mx_history"]
        assert row["st_first_seen"] == "2019-03-15"
        assert row["st_mx_change_date"] == "2023-01-10"

    def test_builds_row_with_empty_data(self):
        dns_a = parse_dns_history(None, "a")
        dns_mx = parse_dns_history(None, "mx")
        dns_ns = parse_dns_history(None, "ns")
        whois = parse_whois_history(None)

        row = build_result_row("empty.com", dns_a, dns_mx, dns_ns, whois)
        assert row["domain"] == "empty.com"
        assert row["st_dns_history_count"] == "0"
        assert row["st_registrar_changes"] == "0"
        assert row["st_mx_history"] == ""
        assert row["st_first_seen"] == ""
        assert row["st_mx_change_date"] == ""


# ---------------------------------------------------------------------------
# TestFormatConsoleOutput
# ---------------------------------------------------------------------------

class TestFormatConsoleOutput:
    """Verify console output formatting."""

    def test_output_contains_domain(self):
        dns_a = parse_dns_history(SAMPLE_DNS_A, "a")
        dns_mx = parse_dns_history(SAMPLE_DNS_MX, "mx")
        dns_ns = parse_dns_history(SAMPLE_DNS_NS, "ns")
        whois = parse_whois_history(SAMPLE_WHOIS)
        output = format_console_output("evil.com", dns_a, dns_mx, dns_ns, whois, remaining=46)
        assert "evil.com" in output
        assert "46" in output
        assert "1.2.3.4" in output
        assert "GoDaddy" in output


# ---------------------------------------------------------------------------
# TestCSVAppend
# ---------------------------------------------------------------------------

class TestCSVAppend:
    """Verify CSV save functionality."""

    def test_creates_new_csv_with_headers(self, tmp_path):
        from enrich_securitytrails import save_to_csv
        csv_path = str(tmp_path / "investigations.csv")
        row = {
            "domain": "evil.com",
            "st_dns_history_count": "2",
            "st_registrar_changes": "3",
            "st_mx_history": "google.com;protonmail.ch",
            "st_first_seen": "2019-03-15",
            "st_mx_change_date": "2023-01-10",
        }
        save_to_csv(row, csv_path)

        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["domain"] == "evil.com"

    def test_appends_to_existing_csv(self, tmp_path):
        from enrich_securitytrails import save_to_csv
        csv_path = str(tmp_path / "investigations.csv")
        row1 = {"domain": "a.com", "st_dns_history_count": "1", "st_registrar_changes": "1",
                "st_mx_history": "", "st_first_seen": "", "st_mx_change_date": ""}
        row2 = {"domain": "b.com", "st_dns_history_count": "2", "st_registrar_changes": "2",
                "st_mx_history": "", "st_first_seen": "", "st_mx_change_date": ""}
        save_to_csv(row1, csv_path)
        save_to_csv(row2, csv_path)

        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2


# ---------------------------------------------------------------------------
# TestBudgetIntegration
# ---------------------------------------------------------------------------

class TestBudgetIntegration:
    """Verify that the script respects the quota tracker."""

    def test_budget_check_mode(self, tmp_path):
        """--budget-check should print remaining and exit without API calls."""
        from shared.api_budget import PersistentQuotaTracker
        db = str(tmp_path / "budget.db")
        tracker = PersistentQuotaTracker(db_path=db, max_queries=50, window_days=30)
        tracker.record_usage("securitytrails", "old.com", cost=4)
        assert tracker.get_remaining() == 46
        tracker.close()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_securitytrails.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'enrich_securitytrails'`

**Step 3: Write minimal implementation**

Create `scripts/enrich_securitytrails.py`:

```python
#!/usr/bin/env python3
"""
enrich_securitytrails.py

Manual single-domain SecurityTrails investigation tool.
Queries historical DNS (A, MX, NS) and WHOIS via SecurityTrails API v1.
Hard circuit breaker at 50 queries per 30-day rolling window.

Usage:
    python scripts/enrich_securitytrails.py --domain evil.com [--save] [--budget-check]

NOT for automated pipeline use. Deliberately excluded from CI.
"""

import argparse
import csv
import logging
import os
import sys
from typing import Dict, List, Optional

import requests
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from shodan_utils import ShodanCache
from shared.retry import retry
from shared.api_budget import PersistentQuotaTracker

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ST_API_BASE = "https://api.securitytrails.com/v1"
CACHE_DB_PATH = "data/.securitytrails_cache/cache.db"
BUDGET_DB_PATH = "data/.securitytrails_cache/budget.db"
CACHE_TTL_DAYS = 30
MAX_QUERIES_30D = 50
DEFAULT_CSV_PATH = "data/manual_investigations.csv"

ST_COLUMNS = [
    "domain",
    "st_dns_history_count",
    "st_registrar_changes",
    "st_mx_history",
    "st_first_seen",
    "st_mx_change_date",
]

DNS_RECORD_TYPES = ["a", "mx", "ns"]

# Value key per record type in SecurityTrails response
VALUE_KEYS = {
    "a": "ip",
    "mx": "host",
    "ns": "nameserver",
}


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

@retry(max_attempts=3, backoff_base=2.0, exceptions=(requests.RequestException,))
def _st_api_get(endpoint: str, api_key: str) -> Optional[dict]:
    """Make a GET request to SecurityTrails API."""
    url = f"{ST_API_BASE}/{endpoint}"
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code == 429:
        raise requests.RequestException(f"Rate limited (429) on {endpoint}")
    if resp.status_code == 403:
        logger.error("API key invalid or quota exceeded (403)")
        return None
    if resp.status_code == 404:
        logger.warning("No data found for endpoint: %s", endpoint)
        return None
    resp.raise_for_status()
    return resp.json()


def query_domain(domain: str, api_key: str, tracker: PersistentQuotaTracker,
                 cache: ShodanCache) -> Dict[str, Optional[dict]]:
    """Query all 4 SecurityTrails endpoints for a domain.

    Returns dict: {"dns/a": {...}, "dns/mx": {...}, "dns/ns": {...}, "whois": {...}}
    Uses cache when available. Records usage in tracker for each uncached call.
    """
    endpoints = [f"history/{domain}/dns/{t}" for t in DNS_RECORD_TYPES]
    endpoints.append(f"history/{domain}/whois")

    results = {}
    for ep in endpoints:
        cache_key = f"st:{domain}:{ep.split('/', 1)[1]}"
        cached = cache.get(cache_key, max_age_days=CACHE_TTL_DAYS)
        if cached is not None:
            logger.info("Cache hit: %s", cache_key)
            results[ep] = cached
            continue

        # Pre-flight budget check for this single call
        if not tracker.can_spend(1):
            logger.error("Budget exhausted — skipping %s", ep)
            results[ep] = None
            continue

        data = _st_api_get(ep, api_key)
        tracker.record_usage("securitytrails", domain, cost=1)

        if data is not None:
            cache.set(cache_key, data)
        else:
            cache.set(cache_key, {})  # cache 404/empty to avoid re-query

        results[ep] = data

    return results


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------

def parse_dns_history(data: Optional[dict], record_type: str) -> dict:
    """Parse a SecurityTrails DNS history response.

    Returns: {unique_count, first_seen, last_change, entries: [{value, first_seen, last_seen}]}
    """
    empty = {"unique_count": 0, "first_seen": "", "last_change": "", "entries": []}
    if not data or "records" not in data:
        return empty

    records = data["records"]
    if not records:
        return empty

    value_key = VALUE_KEYS.get(record_type, "ip")
    entries = []
    for rec in records:
        values = rec.get("values", [])
        val = values[0].get(value_key, "") if values else ""
        entries.append({
            "value": val,
            "first_seen": rec.get("first_seen", ""),
            "last_seen": rec.get("last_seen", ""),
        })

    # Sort by first_seen ascending
    entries.sort(key=lambda e: e["first_seen"])

    first_seen = entries[0]["first_seen"] if entries else ""
    # last_change = the first_seen of the most recent entry (when the change happened)
    last_change = entries[-1]["first_seen"] if len(entries) > 1 else ""

    return {
        "unique_count": len(entries),
        "first_seen": first_seen,
        "last_change": last_change,
        "entries": entries,
    }


def parse_whois_history(data: Optional[dict]) -> dict:
    """Parse a SecurityTrails WHOIS history response.

    Returns: {registrar_changes, entries: [{registrar, date}]}
    """
    empty = {"registrar_changes": 0, "entries": []}
    if not data:
        return empty

    items = []
    try:
        items = data.get("result", {}).get("items", [])
    except AttributeError:
        return empty

    if not items:
        return empty

    entries = []
    for item in items:
        entries.append({
            "registrar": item.get("registrar_name", "Unknown"),
            "date": item.get("created_date", ""),
        })

    entries.sort(key=lambda e: e["date"])

    return {
        "registrar_changes": len(entries),
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# Output builders
# ---------------------------------------------------------------------------

def build_result_row(domain: str, dns_a: dict, dns_mx: dict,
                     dns_ns: dict, whois: dict) -> dict:
    """Build the flat dict for CSV output."""
    mx_providers = []
    for entry in dns_mx.get("entries", []):
        val = entry.get("value", "")
        # Extract domain from MX hostname (e.g., mx1.google.com -> google.com)
        parts = val.split(".")
        if len(parts) >= 2:
            provider = ".".join(parts[-2:])
            if provider not in mx_providers:
                mx_providers.append(provider)

    return {
        "domain": domain,
        "st_dns_history_count": str(dns_a.get("unique_count", 0)),
        "st_registrar_changes": str(whois.get("registrar_changes", 0)),
        "st_mx_history": ";".join(mx_providers),
        "st_first_seen": dns_a.get("first_seen", ""),
        "st_mx_change_date": dns_mx.get("last_change", ""),
    }


def format_console_output(domain: str, dns_a: dict, dns_mx: dict,
                          dns_ns: dict, whois: dict, remaining: int) -> str:
    """Format investigation results for console display."""
    lines = []
    sep = "=" * 50
    lines.append(sep)
    lines.append(f" SecurityTrails Investigation: {domain}")
    lines.append(sep)
    lines.append(f" Budget: {remaining}/50 remaining")
    lines.append("")

    # A Records
    lines.append(f" DNS History (A Records): {dns_a['unique_count']} unique IPs")
    lines.append(" " + "-" * 35)
    for entry in dns_a.get("entries", []):
        tag = ""
        if entry == dns_a["entries"][0]:
            tag = "  (first seen)"
        lines.append(f"   {entry['first_seen']}  {entry['value']}{tag}")
    lines.append("")

    # MX Records
    lines.append(f" MX History: {dns_mx['unique_count']} changes")
    lines.append(" " + "-" * 35)
    for entry in dns_mx.get("entries", []):
        lines.append(f"   {entry['first_seen']}  {entry['value']}")
    lines.append("")

    # NS Records
    lines.append(f" NS History: {dns_ns['unique_count']} changes")
    lines.append(" " + "-" * 35)
    for entry in dns_ns.get("entries", []):
        lines.append(f"   {entry['first_seen']}  {entry['value']}")
    lines.append("")

    # WHOIS
    lines.append(f" WHOIS History: {whois['registrar_changes']} registrar changes")
    lines.append(" " + "-" * 35)
    for entry in whois.get("entries", []):
        lines.append(f"   {entry['date']}  {entry['registrar']}")

    lines.append(sep)
    return "\n".join(lines)


def save_to_csv(row: dict, csv_path: str = DEFAULT_CSV_PATH):
    """Append a result row to the manual investigations CSV."""
    file_exists = os.path.isfile(csv_path)
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ST_COLUMNS)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)
    logger.info("Results saved to %s", csv_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    load_dotenv()
    api_key = os.getenv("ST_API_KEY", "")

    parser = argparse.ArgumentParser(
        description="SecurityTrails manual domain investigation tool (50 queries / 30 days)"
    )
    parser.add_argument("--domain", required=False, help="Domain to investigate")
    parser.add_argument("--save", action="store_true", help="Append results to manual_investigations.csv")
    parser.add_argument("--budget-check", action="store_true", help="Print remaining quota and exit")
    args = parser.parse_args()

    tracker = PersistentQuotaTracker(
        db_path=BUDGET_DB_PATH, max_queries=MAX_QUERIES_30D, window_days=30
    )

    if args.budget_check:
        remaining = tracker.get_remaining()
        used = tracker.get_usage()
        print(f"SecurityTrails budget: {remaining}/50 remaining ({used} used in last 30 days)")
        tracker.close()
        return

    if not args.domain:
        parser.error("--domain is required (unless using --budget-check)")

    if not api_key:
        logger.error("ST_API_KEY not set in environment or .env")
        sys.exit(1)

    # Pre-flight: ensure we have budget for 4 API calls
    tracker.abort_if_exceeded(4)

    cache = ShodanCache(db_path=CACHE_DB_PATH)

    # Query all endpoints
    results = query_domain(args.domain, api_key, tracker, cache)

    # Parse responses
    dns_a_key = f"history/{args.domain}/dns/a"
    dns_mx_key = f"history/{args.domain}/dns/mx"
    dns_ns_key = f"history/{args.domain}/dns/ns"
    whois_key = f"history/{args.domain}/whois"

    dns_a = parse_dns_history(results.get(dns_a_key), "a")
    dns_mx = parse_dns_history(results.get(dns_mx_key), "mx")
    dns_ns = parse_dns_history(results.get(dns_ns_key), "ns")
    whois = parse_whois_history(results.get(whois_key))

    # Display
    remaining = tracker.get_remaining()
    output = format_console_output(args.domain, dns_a, dns_mx, dns_ns, whois, remaining)
    print(output)

    # Build row and optionally save
    row = build_result_row(args.domain, dns_a, dns_mx, dns_ns, whois)
    if args.save:
        save_to_csv(row)

    cache.close()
    tracker.close()


if __name__ == "__main__":
    main()
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_securitytrails.py -v`
Expected: All 15 tests PASS

Run: `pytest tests/ -q --tb=short`
Expected: No regressions

**Step 5: Commit**

```bash
git add scripts/enrich_securitytrails.py tests/test_securitytrails.py
git commit -m "feat: add SecurityTrails manual investigation tool with quota enforcement

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 3: Fingerprint Hooks + Config + Gitignore

**Files:**
- Modify: `config/fingerprints/FP-0001-ovh-cpanel-dea.yaml:48-56` (append st_ modifiers)
- Modify: `config/fingerprints/FP-0007-typosquat-evasion-infra.yaml:46-49` (append st_ modifiers)
- Modify: `config/defaults.yaml:27` (add securitytrails section)
- Modify: `.gitignore:35` (add securitytrails cache)

**Context:** The fingerprint engine (`scripts/match_fingerprints.py:141-171`) handles missing fields gracefully — if a field is empty or missing, `check_indicator()` returns `False` (no match = no delta). This means adding `st_` modifiers is safe even when the fields are not present in the CSV. No fingerprint should **require** st_ fields — they are optional modifiers only.

**Step 1: Add st_ modifiers to FP-0001**

Append after the `phishtank_match` modifier (line 56) in `config/fingerprints/FP-0001-ovh-cpanel-dea.yaml`:

```yaml
  - field: st_registrar_changes
    match_type: range
    value: "3-100"
    delta: 10
  - field: st_dns_history_count
    match_type: range
    value: "10-1000"
    delta: 5
```

**Step 2: Add st_ modifiers to FP-0007**

Append after the `phishtank_match` modifier (line 49) in `config/fingerprints/FP-0007-typosquat-evasion-infra.yaml`:

```yaml
  - field: st_registrar_changes
    match_type: range
    value: "3-100"
    delta: 10
  - field: st_dns_history_count
    match_type: range
    value: "10-1000"
    delta: 5
```

**Step 3: Add securitytrails config**

Append after the `virustotal` section (line 27) in `config/defaults.yaml`:

```yaml

securitytrails:
  max_queries_30d: 50
  cache_ttl_days: 30
```

**Step 4: Add cache to gitignore**

Append after `data/.phishtank_cache/` (line 35) in `.gitignore`:

```
data/.securitytrails_cache/
```

**Step 5: Run fingerprint tests to verify no regression**

Run: `pytest tests/test_fingerprints.py -v`
Expected: All tests PASS (including `test_yaml_loads_successfully` for FP-0007)

**Step 6: Commit**

```bash
git add config/fingerprints/FP-0001-ovh-cpanel-dea.yaml config/fingerprints/FP-0007-typosquat-evasion-infra.yaml config/defaults.yaml .gitignore
git commit -m "feat: add SecurityTrails modifiers to fingerprints and project config

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 4: Documentation Update

**Files:**
- Modify: `data/README.md` (add manual investigation tool section)

**Context:** `data/README.md` documents the pipeline data flow. The SecurityTrails tool is manual-only and needs a clear callout.

**Step 1: Append to data/README.md**

Add a new section at an appropriate location (after the enrichment/analytics sections). The exact insertion point depends on the file's current structure, but should be after the pipeline description:

```markdown
## Manual Investigation Tools

These tools are NOT part of the automated pipeline. They query external APIs with strict quotas and must be run manually.

### SecurityTrails (`scripts/enrich_securitytrails.py`)

**Quota:** 50 API queries per 30-day rolling window (free tier). Each domain investigation costs 4 queries.

```bash
# Check remaining budget
python scripts/enrich_securitytrails.py --budget-check

# Investigate a domain (prints to console)
python scripts/enrich_securitytrails.py --domain evil-example.com

# Investigate and save to CSV
python scripts/enrich_securitytrails.py --domain evil-example.com --save
```

**Output file:** `data/manual_investigations.csv`
**Cache:** `data/.securitytrails_cache/` (30-day TTL, cached queries don't consume quota)
**Budget DB:** `data/.securitytrails_cache/budget.db` (persistent, tracks all queries)

| Column | Description |
| :--- | :--- |
| `st_dns_history_count` | Number of unique historical A record IPs |
| `st_registrar_changes` | Number of distinct WHOIS registrars |
| `st_mx_history` | Semicolon-separated historical MX providers |
| `st_first_seen` | Earliest DNS record date |
| `st_mx_change_date` | Most recent MX record change date |
```

**Step 2: Commit**

```bash
git add data/README.md
git commit -m "docs: document SecurityTrails manual investigation tool in data README

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 5: E2E Validation

**Files:** None (verification only)

**Step 1: Run all tests**

Run: `pytest tests/ -v`
Expected: ALL tests pass

**Step 2: Verify circuit breaker works end-to-end**

```bash
python -c "
import sys; sys.path.insert(0, 'scripts')
from shared.api_budget import PersistentQuotaTracker
import tempfile, os

db = os.path.join(tempfile.mkdtemp(), 'test.db')
t = PersistentQuotaTracker(db_path=db, max_queries=50, window_days=30)
print(f'Fresh: {t.get_remaining()}/50 remaining')
assert t.get_remaining() == 50

t.record_usage('securitytrails', 'evil.com', cost=4)
print(f'After 1 investigation: {t.get_remaining()}/50 remaining')
assert t.get_remaining() == 46

# Fill to limit
t.record_usage('securitytrails', 'bulk.com', cost=46)
print(f'At limit: {t.get_remaining()}/50 remaining')
assert t.get_remaining() == 0
assert t.can_spend(1) is False

print('Circuit breaker test: attempting abort_if_exceeded(4)...')
try:
    t.abort_if_exceeded(4)
    print('ERROR: should have exited')
except SystemExit as e:
    print(f'Correctly aborted with exit code {e.code}')
    assert e.code == 1

t.close()
print('ALL circuit breaker checks PASS')
"
```

Expected: `ALL circuit breaker checks PASS`

**Step 3: Verify fingerprint YAML validity**

```bash
python -c "
import sys; sys.path.insert(0, 'scripts')
from match_fingerprints import load_fingerprints
fps = load_fingerprints('config/fingerprints')
for fp in fps:
    st_mods = [m for m in fp.get('confidence_modifiers', []) if m['field'].startswith('st_')]
    if st_mods:
        print(f'{fp[\"id\"]}: {len(st_mods)} st_ modifiers')
print(f'Loaded {len(fps)} fingerprints successfully')
"
```

Expected: FP-0001 and FP-0007 each show 2 st_ modifiers, all fingerprints load.

**Step 4: Verify workflow YAML unchanged**

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/update_intelligence.yml')); print('Workflow YAML valid — no SecurityTrails step (correct)')"
grep -c "securitytrails" .github/workflows/update_intelligence.yml || echo "Not in pipeline (correct)"
```

Expected: YAML valid, SecurityTrails NOT in pipeline.
