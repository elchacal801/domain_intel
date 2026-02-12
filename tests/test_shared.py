#!/usr/bin/env python3
"""Tests for the shared utilities package."""

import json
import pytest
from unittest.mock import patch, MagicMock
from shared.retry import retry
from shared.cymru_resolver import CymruResolver
from shared.llm_client import LLMClient


# --- retry tests ---

class TestRetry:
    def test_succeeds_first_attempt(self):
        tracker = {"calls": 0}
        
        @retry(max_attempts=3, backoff_base=0.01)
        def always_works():
            tracker["calls"] += 1
            return "ok"
        
        assert always_works() == "ok"
        assert tracker["calls"] == 1

    def test_retries_on_failure_then_succeeds(self):
        tracker = {"calls": 0}
        
        @retry(max_attempts=3, backoff_base=0.01)
        def fails_twice():
            tracker["calls"] += 1
            if tracker["calls"] < 3:
                raise ValueError("transient")
            return "ok"
        
        assert fails_twice() == "ok"
        assert tracker["calls"] == 3

    def test_raises_after_max_attempts(self):
        @retry(max_attempts=2, backoff_base=0.01)
        def always_fails():
            raise RuntimeError("permanent")
        
        with pytest.raises(RuntimeError, match="permanent"):
            always_fails()

    def test_only_catches_specified_exceptions(self):
        @retry(max_attempts=3, backoff_base=0.01, exceptions=(ValueError,))
        def raises_type_error():
            raise TypeError("wrong type")
        
        with pytest.raises(TypeError, match="wrong type"):
            raises_type_error()


# --- CymruResolver tests ---

class TestCymruResolver:
    def test_clean_asn_with_prefix(self):
        assert CymruResolver.clean_asn("AS3333") == "3333"
        
    def test_clean_asn_without_prefix(self):
        assert CymruResolver.clean_asn("3333") == "3333"
    
    def test_clean_asn_lowercase(self):
        assert CymruResolver.clean_asn("as15169") == "15169"
    
    def test_clean_asn_invalid(self):
        assert CymruResolver.clean_asn("not-an-asn") is None
    
    def test_parse_cymru_txt(self):
        resolver = CymruResolver()
        result = resolver._parse_cymru_txt("3333 | NL | ripe | 1993-02-23 | RIPE-NCC-AS")
        assert result["country"] == "NL"
        assert result["name"] == "RIPE-NCC-AS"
        assert result["registry"] == "ripe"
        assert result["date"] == "1993-02-23"


# --- LLMClient tests ---

class TestLLMClient:
    def test_parse_json_clean(self):
        result = LLMClient._parse_json_response('{"key": "value"}')
        assert result == {"key": "value"}
    
    def test_parse_json_with_code_fence(self):
        raw = '```json\n{"key": "value"}\n```'
        result = LLMClient._parse_json_response(raw)
        assert result == {"key": "value"}
    
    def test_parse_json_with_generic_fence(self):
        raw = '```\n{"key": "value"}\n```'
        result = LLMClient._parse_json_response(raw)
        assert result == {"key": "value"}
    
    def test_parse_json_invalid(self):
        result = LLMClient._parse_json_response("not json at all")
        assert result is None
    
    def test_default_model_chain(self):
        client = LLMClient()
        assert len(client.models) >= 3
        assert "anthropic/claude-3-7-sonnet-latest" in client.models[0]
    
    def test_custom_model_chain(self):
        client = LLMClient(models=["model-a", "model-b"])
        assert client.models == ["model-a", "model-b"]
