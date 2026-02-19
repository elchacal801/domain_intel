#!/usr/bin/env python3
"""
shodan_utils.py

Shared utilities for:
1. Shodan Credit Budgeting (Singleton)
2. Local Caching (SQLite)
3. IP Deduplication
"""

import os
import json
import sqlite3
import time
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

# Setup Logging
log = logging.getLogger(__name__)

class CreditBudget:
    """
    Manages Shodan API credit usage per run/month.
    Defaults to FAIL-SAFE (0 credits) if budget file is missing/corrupt.
    """
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(CreditBudget, cls).__new__(cls)
                    cls._instance.budget_file = Path("data/.shodan_budget.json")
                    cls._instance.credits_used_session = 0
                    cls._instance.budget_limit = 0 # Default to 0 (fail-safe)
        return cls._instance

    def set_budget(self, limit: int):
        """Sets the ephemeral budget for this script execution."""
        self.budget_limit = limit
        log.info(f"CreditBudget initialized with limit: {limit}")

    def check_can_spend(self, cost: int = 1) -> bool:
        """Raises exception if over budget."""
        with self._lock:
            if self.credits_used_session + cost > self.budget_limit:
                log.error(f"BUDGET EXCEEDED: Attempted to spend {cost}, used {self.credits_used_session}/{self.budget_limit}")
                return False
            return True

    def spend(self, cost: int = 1):
        """Records credit usage."""
        # Check first (redundant but safe)
        if not self.check_can_spend(cost):
            raise RuntimeError("Shodan Credit Budget Exceeded. Halting.")
        
        with self._lock:
            self.credits_used_session += cost
            log.debug(f"Spent {cost} credit(s). Total session: {self.credits_used_session}/{self.budget_limit}")


class ShodanCache:
    """
    Local SQLite cache for Shodan responses.
    Schema: key (TEXT PRIMARY KEY), data (JSON), timestamp (REAL)
    """
    def __init__(self, db_path: str = "data/.shodan_cache/cache.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True, parents=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False) # simple threading support
        self._init_db()

    def _init_db(self):
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS results (
                key TEXT PRIMARY KEY,
                data TEXT,
                timestamp REAL
            )
        """)
        self.conn.commit()

    def get(self, key: str, max_age_days: int = 30) -> Optional[Dict]:
        """Returns cached data if valid, else None."""
        cur = self.conn.cursor()
        cur.execute("SELECT data, timestamp FROM results WHERE key = ?", (key,))
        row = cur.fetchone()
        
        if row:
            data_str, ts = row
            age_days = (time.time() - ts) / 86400
            if age_days < max_age_days:
                log.debug(f"Cache HIT for {key} (Age: {age_days:.1f} days)")
                return json.loads(data_str)
            else:
                log.debug(f"Cache STALE for {key} (Age: {age_days:.1f} days)")
        
        return None

    def set(self, key: str, data: Dict):
        """Saves data to cache."""
        cur = self.conn.cursor()
        try:
            cur.execute(
                "INSERT OR REPLACE INTO results (key, data, timestamp) VALUES (?, ?, ?)",
                (key, json.dumps(data), time.time())
            )
            self.conn.commit()
        except Exception as e:
            log.error(f"Cache write failed: {e}")

    def close(self):
        self.conn.close()

class IPTracker:
    """Tracks seen IPs to prevent duplicate processing across modules/runs."""
    def __init__(self, state_file: str = "data/.seen_ips.json"):
        self.state_file = Path(state_file)
        self.seen = self._load()

    def _load(self) -> set:
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    return set(json.load(f))
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("Failed to load IP tracker state: %s", exc)
                return set()
        return set()

    def save(self):
        try:
            with open(self.state_file, 'w') as f:
                json.dump(list(self.seen), f)
        except Exception as e:
            log.error(f"Failed to save IP tracker: {e}")

    def is_seen(self, ip: str) -> bool:
        return ip in self.seen

    def mark_seen(self, ip: str):
        self.seen.add(ip)

