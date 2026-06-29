#!/usr/bin/env python3
"""Tests for probe_web.py — redirect capture and title extraction."""

import sys
import os
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from probe_web import fetch, get_title


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    """Run an async coroutine synchronously for testing."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_mock_response(status=200, headers=None, text="", history=None):
    """Create a mock aiohttp response."""
    resp = AsyncMock()
    resp.status = status
    resp.headers = headers or {}
    resp.text = AsyncMock(return_value=text)
    resp.history = history if history is not None else ()
    return resp


def _make_mock_redirect_response():
    """Create a mock response that went through a 301 redirect."""
    redirect_resp = MagicMock()
    redirect_resp.status = 301
    redirect_resp.headers = {"Location": "https://brand.com/"}

    final_resp = AsyncMock()
    final_resp.status = 200
    final_resp.headers = {"Server": "nginx"}
    final_resp.text = AsyncMock(return_value="<html><title>Brand Page</title></html>")
    final_resp.history = (redirect_resp,)
    return final_resp


# ---------------------------------------------------------------------------
# TestGetTitle
# ---------------------------------------------------------------------------

class TestGetTitle:
    def test_extracts_title_from_html(self):
        assert get_title("<html><title>Hello World</title></html>") == "Hello World"

    def test_returns_empty_for_no_title(self):
        assert get_title("<html><body>No title</body></html>") == ""

    def test_returns_empty_for_none(self):
        assert get_title(None) == ""

    def test_truncates_long_title(self):
        long = "A" * 200
        result = get_title(f"<title>{long}</title>")
        assert len(result) == 100


# ---------------------------------------------------------------------------
# TestFetchRedirectCapture
# ---------------------------------------------------------------------------

class TestFetchRedirectCapture:
    """Verify that fetch() captures redirect_status and redirect_target from response.history."""

    def test_redirect_captured_from_history(self):
        mock_resp = _make_mock_redirect_response()

        mock_session = MagicMock()
        mock_session.get = MagicMock()
        mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch('probe_web.asyncio.sleep', new_callable=AsyncMock):
            result = _run(fetch(mock_session, "http://evil.com"))

        assert result["redirect_status"] == "301"
        assert result["redirect_target"] == "https://brand.com/"
        assert result["status"] == "200"
        assert result["title"] == "Brand Page"

    def test_no_redirect_returns_empty(self):
        mock_resp = _make_mock_response(
            status=200,
            headers={"Server": "apache"},
            text="<html><title>Direct</title></html>",
            history=()
        )

        mock_session = MagicMock()
        mock_session.get = MagicMock()
        mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch('probe_web.asyncio.sleep', new_callable=AsyncMock):
            result = _run(fetch(mock_session, "http://example.com"))

        assert result["redirect_status"] == ""
        assert result["redirect_target"] == ""

    def test_connection_error_returns_empty_redirect_fields(self):
        import aiohttp
        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=aiohttp.ClientError("fail"))

        with patch('probe_web.asyncio.sleep', new_callable=AsyncMock):
            result = _run(fetch(mock_session, "http://down.com"))

        assert result["redirect_status"] == ""
        assert result["redirect_target"] == ""
        assert result["status"] == ""
