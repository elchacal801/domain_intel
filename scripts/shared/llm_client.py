#!/usr/bin/env python3
"""
shared/llm_client.py

Centralized LLM interaction wrapper with configurable model fallback chain.
Replaces duplicated litellm patterns across ai_briefing.py, ai_classify_web.py, and ai_typosquat.py.

Usage:
    from shared.llm_client import LLMClient

    client = LLMClient()

    # Text completion
    response = client.complete("Analyze this data...", system="You are an analyst.")

    # JSON completion with automatic parsing
    data = client.complete_json("Classify these domains...", system="Return JSON only.")
"""

import csv
import hashlib
import os
import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv
from litellm import completion

load_dotenv()
logger = logging.getLogger(__name__)

# Central model configuration — single source of truth
# Updated 2026-02-21 per Anthropic API deprecation
DEFAULT_MODEL_CHAIN = [
    "anthropic/claude-sonnet-4-5-20250929",  # Primary (pinned snapshot)
    "gemini/gemini-3-pro-preview",           # Secondary
    "gpt-4o",                                # Tertiary
    "gemini/gemini-flash-latest",            # Emergency fallback
]


def load_model_chain(task_name: str) -> List[str]:
    """Load the model chain for a specific task from config/defaults.yaml.

    Looks up ``ai.<task_name>.model_chain`` via :mod:`shared.config`.
    Falls back to :data:`DEFAULT_MODEL_CHAIN` when the task name is not
    found or the config file is unavailable.

    Args:
        task_name: Task identifier (e.g. "briefing", "classification",
                   "typosquat").

    Returns:
        Ordered list of model identifiers for litellm.
    """
    try:
        from shared.config import get as config_get

        chain = config_get(f"ai.{task_name}.model_chain")
        if isinstance(chain, list) and chain:
            logger.info("Loaded model chain for task '%s': %s", task_name, chain)
            return chain
    except Exception as exc:
        logger.warning("Failed to load model chain for '%s': %s", task_name, exc)

    logger.info("Using DEFAULT_MODEL_CHAIN for task '%s'", task_name)
    return list(DEFAULT_MODEL_CHAIN)


class LLMClient:
    """
    Wrapper around litellm with configurable model fallback chain and JSON output support.

    Features:
    - Automatic fallback through model chain on failure
    - JSON mode with code fence stripping
    - Structured logging of model attempts
    - API key passthrough for services that need explicit keys
    - SQLite-based response caching with configurable TTL
    - Per-call cost tracking to CSV log
    """

    DEFAULT_CACHE_DB = os.path.join("data", ".llm_cache", "llm_cache.db")
    DEFAULT_COST_LOG = os.path.join("data", "llm_cost_log.csv")

    def __init__(
        self,
        models: Optional[List[str]] = None,
        cache_ttl_days: int = 7,
        cache_db_path: Optional[str] = None,
        cost_log_path: Optional[str] = None,
    ):
        """
        Args:
            models: Ordered list of model identifiers for litellm.
                    Falls through the list on failure. Defaults to DEFAULT_MODEL_CHAIN.
            cache_ttl_days: Number of days before cached responses expire. Default 7.
            cache_db_path: Path to the SQLite cache database.
                           Defaults to data/.llm_cache/llm_cache.db.
            cost_log_path: Path to the CSV cost log.
                           Defaults to data/llm_cost_log.csv.
        """
        self.models = models or DEFAULT_MODEL_CHAIN
        self.cache_ttl_days = cache_ttl_days
        self.cache_db_path = cache_db_path or self.DEFAULT_CACHE_DB
        self.cost_log_path = cost_log_path or self.DEFAULT_COST_LOG
        self._cache_conn: Optional[sqlite3.Connection] = None
        self._init_cache()
    
    def close(self):
        """Close the SQLite cache connection."""
        if self._cache_conn:
            self._cache_conn.close()
            self._cache_conn = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def _init_cache(self):
        """Initialize the SQLite cache database and table."""
        db_path = Path(self.cache_db_path)
        db_path.parent.mkdir(exist_ok=True, parents=True)
        self._cache_conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._cache_conn.execute("""
            CREATE TABLE IF NOT EXISTS llm_cache (
                cache_key TEXT PRIMARY KEY,
                model TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp REAL NOT NULL
            )
        """)
        self._cache_conn.commit()

    @staticmethod
    def _cache_key(system: str, prompt: str, json_mode: bool, temperature: float) -> str:
        """Generate a deterministic SHA-256 cache key from request parameters.

        The key is model-agnostic: any model's response for the same prompt is
        interchangeable for cost-saving purposes.  This means a cached response
        from a fallback model will be served on subsequent calls even if the
        primary model is available again.
        """
        key_material = json.dumps(
            [system, prompt, json_mode, temperature],
            sort_keys=True,
        )
        return hashlib.sha256(key_material.encode("utf-8")).hexdigest()

    def _cache_get(self, cache_key: str) -> Optional[str]:
        """Return cached content if it exists and has not expired, else None."""
        cutoff = time.time() - (self.cache_ttl_days * 86400)
        cur = self._cache_conn.execute(
            "SELECT content FROM llm_cache WHERE cache_key = ? AND timestamp > ?",
            (cache_key, cutoff),
        )
        row = cur.fetchone()
        return row[0] if row else None

    def _cache_put(self, cache_key: str, model: str, content: str):
        """Insert or replace a cache entry."""
        self._cache_conn.execute(
            "INSERT OR REPLACE INTO llm_cache (cache_key, model, content, timestamp) "
            "VALUES (?, ?, ?, ?)",
            (cache_key, model, content, time.time()),
        )
        self._cache_conn.commit()

    # ------------------------------------------------------------------
    # Cost tracking
    # ------------------------------------------------------------------

    def _log_cost(
        self,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: int,
        cached: bool,
    ):
        """Append a row to the cost log CSV. Creates the file with header if needed."""
        log_path = Path(self.cost_log_path)
        log_path.parent.mkdir(exist_ok=True, parents=True)
        write_header = not log_path.exists() or log_path.stat().st_size == 0
        with open(log_path, "a", newline="") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow([
                    "timestamp", "model", "prompt_tokens",
                    "completion_tokens", "total_tokens", "cached",
                ])
            writer.writerow([
                datetime.now(timezone.utc).isoformat(),
                model,
                prompt_tokens,
                completion_tokens,
                total_tokens,
                cached,
            ])

    # ------------------------------------------------------------------
    # API key helpers
    # ------------------------------------------------------------------

    def _get_api_key(self, model: str) -> Optional[str]:
        """Returns the appropriate API key for models that need explicit passthrough."""
        if "anthropic" in model:
            return os.getenv("ANTHROPIC_API_KEY")
        return None
    
    def complete(
        self,
        prompt: str,
        system: str = "",
        json_mode: bool = False,
        temperature: float = 0.3,
        use_cache: bool = True,
    ) -> Optional[str]:
        """
        Send a completion request, trying each model in the chain until one succeeds.

        Args:
            prompt: User message content.
            system: System message content.
            json_mode: If True, requests JSON response format.
            temperature: Sampling temperature.
            use_cache: If True (default), check/store results in the SQLite cache.

        Returns:
            The response content string, or None if all models fail.
        """
        # --- Cache lookup (model-agnostic key) ---
        cache_key = self._cache_key(system, prompt, json_mode, temperature)

        if use_cache:
            cached_content = self._cache_get(cache_key)
            if cached_content is not None:
                logger.info(f"Cache hit (hash: {cache_key[:8]})")
                self._log_cost(
                    model="cache",
                    prompt_tokens=0,
                    completion_tokens=0,
                    total_tokens=0,
                    cached=True,
                )
                return cached_content

        # --- Build request ---
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        kwargs: Dict[str, Any] = {
            "messages": messages,
            "temperature": temperature,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        last_error = None
        model_used = None

        for model in self.models:
            try:
                logger.info(f"Attempting completion with {model}...")

                api_key = self._get_api_key(model)
                if api_key:
                    kwargs["api_key"] = api_key
                elif "api_key" in kwargs:
                    del kwargs["api_key"]

                response = completion(model=model, **kwargs)
                content = response.choices[0].message.content
                model_used = getattr(response, 'model', model)

                logger.info(f"Success with {model_used}")

                # --- Cost tracking ---
                usage = getattr(response, 'usage', None)
                prompt_tokens = getattr(usage, 'prompt_tokens', 0) or 0
                completion_tokens = getattr(usage, 'completion_tokens', 0) or 0
                total_tokens = prompt_tokens + completion_tokens
                self._log_cost(
                    model=model_used,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    cached=False,
                )

                # --- Store in cache ---
                if use_cache:
                    self._cache_put(cache_key, model_used, content)

                return content

            except Exception as e:
                last_error = e
                logger.warning(f"{model} failed: {e}")
                continue

        logger.error(f"All {len(self.models)} models failed. Last error: {last_error}")
        return None
    
    def complete_json(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.3,
        use_cache: bool = True,
    ) -> Optional[Dict]:
        """
        Send a completion request and parse the response as JSON.

        Handles common LLM output quirks:
        - Code fences (```json ... ```)
        - Leading/trailing whitespace
        - Markdown formatting artifacts

        Args:
            prompt: User message content.
            system: System message content.
            temperature: Sampling temperature.
            use_cache: If True (default), check/store results in the SQLite cache.

        Returns:
            Parsed JSON as a dict, or None if all models fail or JSON is invalid.
        """
        content = self.complete(
            prompt, system=system, json_mode=True,
            temperature=temperature, use_cache=use_cache,
        )
        
        if content is None:
            return None
        
        return self._parse_json_response(content)
    
    @staticmethod
    def _parse_json_response(content: str) -> Optional[Dict]:
        """
        Extracts and parses JSON from LLM response text.
        Handles code fences and other formatting artifacts.
        """
        # Strip code fences
        cleaned = content.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json", 1)[1]
            if "```" in cleaned:
                cleaned = cleaned.split("```", 1)[0]
        elif "```" in cleaned:
            # Generic code fence
            parts = cleaned.split("```")
            if len(parts) >= 3:
                cleaned = parts[1]
            else:
                cleaned = cleaned.replace("```", "")
        
        try:
            return json.loads(cleaned.strip())
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from LLM response: {e}")
            logger.debug(f"Raw content: {content[:500]}")
            return None
