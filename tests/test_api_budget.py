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
