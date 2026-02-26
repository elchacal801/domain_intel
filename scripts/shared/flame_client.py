#!/usr/bin/env python3
"""
shared/flame_client.py

Client for the FLAME (Fraud Lifecycle Attack Map & Encyclopedia) threat-path
index published at GitHub Pages by the companion *flame-fraud* project.

Features:
- Fetches ``flame-index.json`` from the URL stored in ``config/defaults.yaml``
- Caches locally in ``data/.flame_cache/index.json`` with configurable TTL
- Graceful degradation: returns cached version or empty list on failure
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from shared import config as cfg

logger = logging.getLogger(__name__)

# Defaults (overridden by config/defaults.yaml when present)
_DEFAULT_INDEX_URL = "https://elchacal801.github.io/flame-fraud/database/flame-index.json"
_DEFAULT_CACHE_TTL_HOURS = 24

# Cache location (relative to CWD which is normally the repo root)
_CACHE_DIR = Path("data/.flame_cache")
_CACHE_FILE = _CACHE_DIR / "index.json"
_CACHE_META = _CACHE_DIR / ".meta.json"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _index_url() -> str:
    """Resolve the FLAME index URL from config, falling back to default."""
    return cfg.get("flame.index_url", _DEFAULT_INDEX_URL)


def _cache_ttl_seconds() -> float:
    """Resolve the cache TTL in seconds from config."""
    hours = cfg.get("flame.cache_ttl_hours", _DEFAULT_CACHE_TTL_HOURS)
    return float(hours) * 3600


def _load_cache() -> Optional[List[Dict[str, Any]]]:
    """Return cached threat-path list if the cache exists and is fresh."""
    if not _CACHE_FILE.exists() or not _CACHE_META.exists():
        return None

    try:
        with open(_CACHE_META, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
        fetched_at = meta.get("fetched_at", 0)
        if (time.time() - fetched_at) > _cache_ttl_seconds():
            logger.debug("FLAME cache is stale (age %.1f h)", (time.time() - fetched_at) / 3600)
            return None

        with open(_CACHE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        logger.debug("FLAME cache hit (%d threat paths)", len(data))
        return data
    except (json.JSONDecodeError, OSError, KeyError) as exc:
        logger.warning("Failed to read FLAME cache: %s", exc)
        return None


def _save_cache(data: List[Dict[str, Any]]) -> None:
    """Persist threat-path data and timestamp to disk."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with open(_CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        with open(_CACHE_META, "w", encoding="utf-8") as fh:
            json.dump({"fetched_at": time.time()}, fh)
        logger.debug("FLAME cache saved (%d threat paths)", len(data))
    except OSError as exc:
        logger.warning("Failed to write FLAME cache: %s", exc)


def _fetch_index() -> Optional[List[Dict[str, Any]]]:
    """Download flame-index.json from the configured URL."""
    url = _index_url()
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        logger.warning("FLAME index is not a JSON array — ignoring")
        return None
    except requests.RequestException as exc:
        logger.warning("Failed to fetch FLAME index from %s: %s", url, exc)
        return None
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("Invalid JSON in FLAME index: %s", exc)
        return None


def _force_cache_fallback() -> List[Dict[str, Any]]:
    """Return whatever is on disk regardless of TTL, or empty list."""
    if _CACHE_FILE.exists():
        try:
            with open(_CACHE_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            logger.info("Using stale FLAME cache (%d threat paths)", len(data))
            return data
        except (json.JSONDecodeError, OSError):
            pass
    return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_threat_paths() -> List[Dict[str, Any]]:
    """Return all FLAME threat paths, using cache when fresh.

    Resolution order:
    1. Fresh local cache  → return immediately
    2. Network fetch      → cache & return
    3. Stale local cache  → return with warning
    4. Nothing available  → return ``[]``
    """
    # 1. Check cache
    cached = _load_cache()
    if cached is not None:
        return cached

    # 2. Fetch from network
    data = _fetch_index()
    if data is not None:
        _save_cache(data)
        return data

    # 3. Stale cache fallback
    return _force_cache_fallback()


def get_tp_summaries_for_prompt() -> str:
    """Build a compact reference string suitable for LLM prompt injection.

    Each threat path is rendered as::

        - TP-0001: Treasury Management ATO via Malvertising and Vishing -- Threat actors target...

    Returns:
        A multi-line string with all threat paths, or an empty string if
        the index is unavailable.
    """
    paths = get_threat_paths()
    if not paths:
        return ""

    lines = ["FLAME Threat Path Taxonomy (map each domain to zero or more of these IDs):"]
    for tp in paths:
        tp_id = tp.get("id", "??")
        title = tp.get("title", "Untitled")
        summary = tp.get("summary", "")
        # Truncate summary to keep prompt size manageable
        if len(summary) > 180:
            summary = summary[:177] + "..."
        lines.append(f"- {tp_id}: {title} -- {summary}")

    return "\n".join(lines)
