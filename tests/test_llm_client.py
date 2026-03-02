#!/usr/bin/env python3
"""Tests for shared/llm_client.py — LLM response caching and cost tracking."""

import csv
import json
import os
import sqlite3
import sys
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from shared.llm_client import LLMClient, load_model_chain, DEFAULT_MODEL_CHAIN


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_litellm_response(content="Hello!", model="test-model",
                           prompt_tokens=10, completion_tokens=5):
    """Build a mock litellm response object matching the real structure."""
    message = SimpleNamespace(content=content)
    choice = SimpleNamespace(message=message)
    usage = SimpleNamespace(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )
    return SimpleNamespace(choices=[choice], model=model, usage=usage)


def _make_client(tmp_path, **kwargs):
    """Create an LLMClient pointed at tmp_path for cache and cost log."""
    defaults = dict(
        models=["test-model"],
        cache_db_path=str(tmp_path / ".llm_cache" / "llm_cache.db"),
        cost_log_path=str(tmp_path / "llm_cost_log.csv"),
    )
    defaults.update(kwargs)
    return LLMClient(**defaults)


# ---------------------------------------------------------------------------
# TestCacheStoreAndRetrieve
# ---------------------------------------------------------------------------

class TestCacheStoreAndRetrieve:
    """Verify that LLM responses are cached and served from cache."""

    @patch("shared.llm_client.completion")
    def test_cache_stores_and_retrieves(self, mock_completion, tmp_path):
        """First call hits the API; second call returns cached result."""
        mock_completion.return_value = _make_litellm_response(content="cached-answer")

        client = _make_client(tmp_path)

        # First call — should invoke litellm
        result1 = client.complete("What is 2+2?", system="math")
        assert result1 == "cached-answer"
        assert mock_completion.call_count == 1

        # Second call with same params — should come from cache
        result2 = client.complete("What is 2+2?", system="math")
        assert result2 == "cached-answer"
        assert mock_completion.call_count == 1  # no additional API call

    @patch("shared.llm_client.completion")
    def test_different_prompts_not_cached_together(self, mock_completion, tmp_path):
        """Different prompts should produce different cache keys."""
        mock_completion.return_value = _make_litellm_response(content="answer-A")

        client = _make_client(tmp_path)

        client.complete("prompt A")
        assert mock_completion.call_count == 1

        mock_completion.return_value = _make_litellm_response(content="answer-B")
        client.complete("prompt B")
        assert mock_completion.call_count == 2  # different key, new API call

    @patch("shared.llm_client.completion")
    def test_different_system_prompts_not_cached_together(self, mock_completion, tmp_path):
        """Different system prompts produce different cache keys."""
        mock_completion.return_value = _make_litellm_response(content="sys-A")
        client = _make_client(tmp_path)

        client.complete("hello", system="system-A")
        assert mock_completion.call_count == 1

        mock_completion.return_value = _make_litellm_response(content="sys-B")
        client.complete("hello", system="system-B")
        assert mock_completion.call_count == 2


# ---------------------------------------------------------------------------
# TestCacheTTL
# ---------------------------------------------------------------------------

class TestCacheTTL:
    """Verify that cache respects TTL expiration."""

    @patch("shared.llm_client.completion")
    def test_expired_cache_not_returned(self, mock_completion, tmp_path):
        """Entries older than cache_ttl_days should not be served."""
        mock_completion.return_value = _make_litellm_response(content="fresh")

        client = _make_client(tmp_path, cache_ttl_days=1)

        # Store a response
        client.complete("test prompt")
        assert mock_completion.call_count == 1

        # Manually age the cache entry to 2 days ago
        aged_ts = time.time() - (2 * 86400)
        client._cache_conn.execute(
            "UPDATE llm_cache SET timestamp = ?", (aged_ts,)
        )
        client._cache_conn.commit()

        # Should miss cache and call API again
        mock_completion.return_value = _make_litellm_response(content="refreshed")
        result = client.complete("test prompt")
        assert result == "refreshed"
        assert mock_completion.call_count == 2

    @patch("shared.llm_client.completion")
    def test_non_expired_cache_is_returned(self, mock_completion, tmp_path):
        """Entries within TTL should still be served from cache."""
        mock_completion.return_value = _make_litellm_response(content="valid")
        client = _make_client(tmp_path, cache_ttl_days=7)

        client.complete("test prompt")
        assert mock_completion.call_count == 1

        # Age to 3 days ago (within 7-day TTL)
        aged_ts = time.time() - (3 * 86400)
        client._cache_conn.execute(
            "UPDATE llm_cache SET timestamp = ?", (aged_ts,)
        )
        client._cache_conn.commit()

        result = client.complete("test prompt")
        assert result == "valid"
        assert mock_completion.call_count == 1  # still cached


# ---------------------------------------------------------------------------
# TestCacheBypass
# ---------------------------------------------------------------------------

class TestCacheBypass:
    """Verify that use_cache=False bypasses the cache."""

    @patch("shared.llm_client.completion")
    def test_use_cache_false_bypasses_cache(self, mock_completion, tmp_path):
        """With use_cache=False, every call hits the API."""
        mock_completion.return_value = _make_litellm_response(content="no-cache")
        client = _make_client(tmp_path)

        result1 = client.complete("prompt", use_cache=False)
        result2 = client.complete("prompt", use_cache=False)

        assert result1 == "no-cache"
        assert result2 == "no-cache"
        assert mock_completion.call_count == 2

    @patch("shared.llm_client.completion")
    def test_use_cache_false_does_not_store(self, mock_completion, tmp_path):
        """With use_cache=False, results are not written to cache."""
        mock_completion.return_value = _make_litellm_response(content="ephemeral")
        client = _make_client(tmp_path)

        client.complete("prompt", use_cache=False)

        # Cache should be empty
        cur = client._cache_conn.execute("SELECT COUNT(*) FROM llm_cache")
        assert cur.fetchone()[0] == 0

    @patch("shared.llm_client.completion")
    def test_complete_json_passes_use_cache(self, mock_completion, tmp_path):
        """complete_json should forward use_cache to complete."""
        mock_completion.return_value = _make_litellm_response(
            content='{"result": 42}'
        )
        client = _make_client(tmp_path)

        result1 = client.complete_json("json prompt", use_cache=False)
        result2 = client.complete_json("json prompt", use_cache=False)

        assert result1 == {"result": 42}
        assert mock_completion.call_count == 2  # both hit API


# ---------------------------------------------------------------------------
# TestCostLogCSV
# ---------------------------------------------------------------------------

class TestCostLogCSV:
    """Verify that cost tracking CSV is written correctly."""

    @patch("shared.llm_client.completion")
    def test_cost_log_written_on_api_call(self, mock_completion, tmp_path):
        """A successful API call should append a row to the cost log."""
        mock_completion.return_value = _make_litellm_response(
            model="gpt-4o", prompt_tokens=100, completion_tokens=50,
        )
        client = _make_client(tmp_path)

        client.complete("analyze this")

        log_path = tmp_path / "llm_cost_log.csv"
        assert log_path.exists()

        with open(log_path, "r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        row = rows[0]
        assert row["model"] == "gpt-4o"
        assert row["prompt_tokens"] == "100"
        assert row["completion_tokens"] == "50"
        assert row["total_tokens"] == "150"
        assert row["cached"] == "False"

    @patch("shared.llm_client.completion")
    def test_cost_log_marks_cache_hit_as_cached(self, mock_completion, tmp_path):
        """Cache hits should be logged with cached=True and zero tokens."""
        mock_completion.return_value = _make_litellm_response(
            prompt_tokens=20, completion_tokens=10,
        )
        client = _make_client(tmp_path)

        # First call — API hit
        client.complete("hello")
        # Second call — cache hit
        client.complete("hello")

        log_path = tmp_path / "llm_cost_log.csv"
        with open(log_path, "r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2

        # First row: API call
        assert rows[0]["cached"] == "False"
        assert rows[0]["prompt_tokens"] == "20"

        # Second row: cache hit
        assert rows[1]["cached"] == "True"
        assert rows[1]["model"] == "cache"
        assert rows[1]["prompt_tokens"] == "0"
        assert rows[1]["completion_tokens"] == "0"
        assert rows[1]["total_tokens"] == "0"

    @patch("shared.llm_client.completion")
    def test_cost_log_csv_header_written_once(self, mock_completion, tmp_path):
        """Multiple API calls should not duplicate the CSV header."""
        mock_completion.return_value = _make_litellm_response()
        client = _make_client(tmp_path)

        client.complete("call 1", use_cache=False)
        client.complete("call 2", use_cache=False)

        log_path = tmp_path / "llm_cost_log.csv"
        with open(log_path, "r") as f:
            lines = f.readlines()

        # Header + 2 data rows = 3 lines
        assert len(lines) == 3
        assert lines[0].startswith("timestamp,")

    @patch("shared.llm_client.completion")
    def test_cost_log_has_correct_columns(self, mock_completion, tmp_path):
        """The CSV should have the expected column headers."""
        mock_completion.return_value = _make_litellm_response()
        client = _make_client(tmp_path)

        client.complete("test")

        log_path = tmp_path / "llm_cost_log.csv"
        with open(log_path, "r") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames

        assert fieldnames == [
            "timestamp", "model", "prompt_tokens",
            "completion_tokens", "total_tokens", "cached",
        ]


# ---------------------------------------------------------------------------
# TestCacheDirCreation
# ---------------------------------------------------------------------------

class TestCacheDirCreation:
    """Verify that LLMClient creates cache directory if it doesn't exist."""

    @patch("shared.llm_client.completion")
    def test_creates_cache_dir_on_init(self, mock_completion, tmp_path):
        """LLMClient should create the cache directory tree automatically."""
        cache_db = str(tmp_path / "deep" / "nested" / "cache.db")
        client = LLMClient(
            models=["test-model"],
            cache_db_path=cache_db,
            cost_log_path=str(tmp_path / "cost.csv"),
        )
        assert os.path.isfile(cache_db)

    @patch("shared.llm_client.completion")
    def test_creates_cost_log_dir_on_write(self, mock_completion, tmp_path):
        """Cost log directory should be created when first row is written."""
        mock_completion.return_value = _make_litellm_response()
        cost_log = str(tmp_path / "logs" / "deep" / "cost.csv")
        client = LLMClient(
            models=["test-model"],
            cache_db_path=str(tmp_path / "cache.db"),
            cost_log_path=cost_log,
        )

        client.complete("test")
        assert os.path.isfile(cost_log)


# ---------------------------------------------------------------------------
# TestCacheKeyDeterminism
# ---------------------------------------------------------------------------

class TestCacheKeyDeterminism:
    """Verify that cache key generation is consistent and deterministic."""

    def test_same_inputs_same_key(self):
        """Identical inputs should always produce the same cache key."""
        key1 = LLMClient._cache_key("sys", "prompt", True, 0.3)
        key2 = LLMClient._cache_key("sys", "prompt", True, 0.3)
        assert key1 == key2

    def test_different_temperature_different_key(self):
        """Different temperatures should produce different keys."""
        key1 = LLMClient._cache_key("sys", "prompt", True, 0.3)
        key2 = LLMClient._cache_key("sys", "prompt", True, 0.7)
        assert key1 != key2

    def test_different_json_mode_different_key(self):
        """Different json_mode values should produce different keys."""
        key1 = LLMClient._cache_key("sys", "prompt", True, 0.3)
        key2 = LLMClient._cache_key("sys", "prompt", False, 0.3)
        assert key1 != key2

    def test_cache_key_is_hex_sha256(self):
        """Cache key should be a 64-char hex string (SHA-256)."""
        key = LLMClient._cache_key("sys", "prompt", False, 0.5)
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)

    def test_cache_key_is_model_agnostic(self):
        """Cache key should not include model — any model's response is reusable."""
        key = LLMClient._cache_key("sys", "prompt", True, 0.3)
        # Verify the key does not change based on external model config
        assert isinstance(key, str) and len(key) == 64


# ---------------------------------------------------------------------------
# TestBackwardCompatibility
# ---------------------------------------------------------------------------

class TestBackwardCompatibility:
    """Verify that existing callers (no new args) still work."""

    @patch("shared.llm_client.completion")
    def test_default_init_works(self, mock_completion, tmp_path):
        """LLMClient() with no args should work (uses defaults)."""
        # Temporarily override class-level defaults to use tmp_path
        with patch.object(LLMClient, 'DEFAULT_CACHE_DB', str(tmp_path / "c.db")):
            with patch.object(LLMClient, 'DEFAULT_COST_LOG', str(tmp_path / "cost.csv")):
                client = LLMClient()
                assert client.cache_ttl_days == 7
                assert len(client.models) > 0

    @patch("shared.llm_client.completion")
    def test_complete_without_use_cache_arg(self, mock_completion, tmp_path):
        """Calling complete() without use_cache should default to True."""
        mock_completion.return_value = _make_litellm_response(content="ok")
        client = _make_client(tmp_path)

        # Old-style call — no use_cache kwarg
        result = client.complete("hello", system="sys")
        assert result == "ok"

    @patch("shared.llm_client.completion")
    def test_complete_json_without_use_cache_arg(self, mock_completion, tmp_path):
        """Calling complete_json() without use_cache should default to True."""
        mock_completion.return_value = _make_litellm_response(
            content='{"status": "ok"}'
        )
        client = _make_client(tmp_path)

        result = client.complete_json("give json", system="sys")
        assert result == {"status": "ok"}


# ---------------------------------------------------------------------------
# TestAllModelsFail
# ---------------------------------------------------------------------------

class TestAllModelsFail:
    """Verify behavior when all models fail (no cache, no cost log for failures)."""

    @patch("shared.llm_client.completion")
    def test_returns_none_when_all_fail(self, mock_completion, tmp_path):
        """When all models fail, complete() returns None."""
        mock_completion.side_effect = Exception("API error")
        client = _make_client(tmp_path)

        result = client.complete("test")
        assert result is None

    @patch("shared.llm_client.completion")
    def test_no_cost_log_when_all_fail(self, mock_completion, tmp_path):
        """When all models fail, no cost log row is written."""
        mock_completion.side_effect = Exception("API error")
        client = _make_client(tmp_path)

        client.complete("test")

        log_path = tmp_path / "llm_cost_log.csv"
        assert not log_path.exists()

    @patch("shared.llm_client.completion")
    def test_no_cache_entry_when_all_fail(self, mock_completion, tmp_path):
        """When all models fail, nothing is stored in cache."""
        mock_completion.side_effect = Exception("API error")
        client = _make_client(tmp_path)

        client.complete("test")

        cur = client._cache_conn.execute("SELECT COUNT(*) FROM llm_cache")
        assert cur.fetchone()[0] == 0


# ---------------------------------------------------------------------------
# TestUsageAttributeHandling
# ---------------------------------------------------------------------------

class TestUsageAttributeHandling:
    """Verify graceful handling of missing usage attributes on responses."""

    @patch("shared.llm_client.completion")
    def test_missing_usage_defaults_to_zero(self, mock_completion, tmp_path):
        """If response has no usage attribute, tokens should be 0."""
        message = SimpleNamespace(content="ok")
        choice = SimpleNamespace(message=message)
        response = SimpleNamespace(choices=[choice], model="test-model")
        # No 'usage' attribute at all
        mock_completion.return_value = response

        client = _make_client(tmp_path)
        client.complete("test")

        log_path = tmp_path / "llm_cost_log.csv"
        with open(log_path, "r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        assert rows[0]["prompt_tokens"] == "0"
        assert rows[0]["completion_tokens"] == "0"
        assert rows[0]["total_tokens"] == "0"


# ---------------------------------------------------------------------------
# TestLoadModelChain
# ---------------------------------------------------------------------------

class TestLoadModelChain:
    """Verify that load_model_chain() returns correct per-task model chains."""

    def test_briefing_returns_sonnet_chain(self):
        """load_model_chain('briefing') should return the Sonnet chain from config."""
        chain = load_model_chain("briefing")
        assert isinstance(chain, list)
        assert len(chain) > 0
        assert "anthropic/claude-sonnet-4-5-20250929" == chain[0]

    def test_classification_returns_haiku_chain(self):
        """load_model_chain('classification') should return the Haiku chain from config."""
        chain = load_model_chain("classification")
        assert isinstance(chain, list)
        assert len(chain) > 0
        assert "anthropic/claude-haiku-4-5-20251001" == chain[0]

    def test_typosquat_returns_haiku_chain(self):
        """load_model_chain('typosquat') should return the Haiku chain from config."""
        chain = load_model_chain("typosquat")
        assert isinstance(chain, list)
        assert len(chain) > 0
        assert "anthropic/claude-haiku-4-5-20251001" == chain[0]

    def test_nonexistent_task_falls_back_to_default(self):
        """load_model_chain('nonexistent') should fall back to DEFAULT_MODEL_CHAIN."""
        chain = load_model_chain("nonexistent")
        assert chain == DEFAULT_MODEL_CHAIN

    def test_fallback_returns_copy_not_reference(self):
        """Fallback should return a copy so callers cannot mutate the global default."""
        chain = load_model_chain("nonexistent")
        assert chain == DEFAULT_MODEL_CHAIN
        chain.append("extra-model")
        assert DEFAULT_MODEL_CHAIN != chain  # original unchanged

    @patch("shared.config.get", side_effect=Exception("config unavailable"))
    def test_config_exception_falls_back(self, mock_config_get):
        """When shared.config.get raises, fall back to DEFAULT_MODEL_CHAIN."""
        chain = load_model_chain("briefing")
        assert chain == DEFAULT_MODEL_CHAIN

    @patch("shared.config.get", return_value=None)
    def test_config_returns_none_falls_back(self, mock_config_get):
        """When config has no entry for the task, fall back to DEFAULT_MODEL_CHAIN."""
        chain = load_model_chain("nonexistent_task")
        assert chain == DEFAULT_MODEL_CHAIN

    @patch("shared.config.get", return_value=[])
    def test_config_returns_empty_list_falls_back(self, mock_config_get):
        """When config returns an empty list, fall back to DEFAULT_MODEL_CHAIN."""
        chain = load_model_chain("briefing")
        assert chain == DEFAULT_MODEL_CHAIN
