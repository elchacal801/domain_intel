#!/usr/bin/env python3
"""
shared/config.py

Centralised configuration for domain_intel.

- Loads ``config/defaults.yaml`` relative to the repository root.
- Validates required environment variables at import time (warnings only,
  so scripts that don't need a particular service can still start).
- Provides a ``get(key, default=None)`` accessor with dot-notation support.
"""

import logging
import os
from pathlib import Path
from typing import Any, Optional

import yaml
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Locate config/defaults.yaml
# ---------------------------------------------------------------------------
# scripts/shared/config.py  →  scripts/  →  repo root
_SCRIPT_DIR = Path(__file__).resolve().parent.parent
_REPO_ROOT = _SCRIPT_DIR.parent
_DEFAULTS_PATH = _REPO_ROOT / "config" / "defaults.yaml"

_defaults: dict = {}

if _DEFAULTS_PATH.exists():
    try:
        with open(_DEFAULTS_PATH, "r", encoding="utf-8") as fh:
            _defaults = yaml.safe_load(fh) or {}
        logger.debug("Loaded defaults from %s", _DEFAULTS_PATH)
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to load %s: %s", _DEFAULTS_PATH, exc)
else:
    logger.info("No defaults.yaml found at %s — using built-in fallbacks", _DEFAULTS_PATH)

# ---------------------------------------------------------------------------
# Env-var validation (warn-only so optional integrations don't block startup)
# ---------------------------------------------------------------------------
_REQUIRED_ENV_VARS = {
    "ANTHROPIC_API_KEY": "Required for Claude models (primary LLM). Also accepted as CLAUDE_API_KEY.",
    "ALIENVAULT_OTX_API_KEY": "Required for OTX passive DNS pivots.",
    "SHODAN_API_KEY": "Required for Shodan campaign hunting.",
}


def _validate_env_vars() -> None:
    """Log warnings for missing environment variables."""
    for var, description in _REQUIRED_ENV_VARS.items():
        if var == "ANTHROPIC_API_KEY":
            # Accept either name
            if not (os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_API_KEY")):
                logger.warning("Missing env var %s — %s", var, description)
        elif not os.getenv(var):
            logger.warning("Missing env var %s — %s", var, description)


_validate_env_vars()


# ---------------------------------------------------------------------------
# Public accessor
# ---------------------------------------------------------------------------

def get(key: str, default: Any = None) -> Any:
    """Retrieve a config value using dot-notation.

    Examples::

        >>> config.get("flame.index_url")
        'https://elchacal801.github.io/flame-fraud/flame-index.json'
        >>> config.get("ai.batch_size", 50)
        100
        >>> config.get("nonexistent.key", "fallback")
        'fallback'

    Args:
        key:     Dot-separated path into ``defaults.yaml``.
        default: Value returned when the key is absent.

    Returns:
        The configuration value, or *default*.
    """
    parts = key.split(".")
    node: Any = _defaults
    for part in parts:
        if isinstance(node, dict):
            node = node.get(part)
        else:
            return default
        if node is None:
            return default
    return node
