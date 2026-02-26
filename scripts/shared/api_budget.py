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
