"""Tests for visual_fingerprint screenshot capture."""

import asyncio
import os
import sys
from unittest.mock import patch

import pytest

pytest.importorskip("playwright")
pytest.importorskip("imagehash")
pytest.importorskip("PIL")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import visual_fingerprint as vf
from playwright.async_api import Error as PlaywrightError


class FakePage:
    """Records whether it was closed, so leaks are detectable."""

    def __init__(self, registry, goto_error=True):
        self.closed = False
        self.goto_error = goto_error
        registry.append(self)

    async def goto(self, url, timeout=None, wait_until=None):
        if self.goto_error:
            raise PlaywrightError("net::ERR_CONNECTION_REFUSED")

    async def screenshot(self, full_page=False):
        raise AssertionError("screenshot should not run after goto failure")

    async def close(self):
        self.closed = True


class FakeContext:
    def __init__(self, registry):
        self._registry = registry

    async def new_page(self):
        return FakePage(self._registry)


class FakeBrowser:
    def __init__(self, registry):
        self._registry = registry

    async def new_context(self, **kwargs):
        return FakeContext(self._registry)

    async def close(self):
        pass


class FakeChromium:
    def __init__(self, registry):
        self._registry = registry

    async def launch(self, headless=True):
        return FakeBrowser(self._registry)


class FakePlaywright:
    def __init__(self, registry):
        self.chromium = FakeChromium(registry)


class FakePlaywrightCM:
    def __init__(self, registry):
        self._registry = registry

    async def __aenter__(self):
        return FakePlaywright(self._registry)

    async def __aexit__(self, *exc):
        return False


class TestPageLifecycle:
    """Pages must never leak, regardless of which path a domain takes."""

    def test_page_closed_when_all_protocols_fail(self):
        """Unreachable over both HTTP and HTTPS must still close the page.

        Leaked pages accumulate in the browser across a large scan and
        degrade it until the step stalls (see run 32459415652).
        """
        registry = []
        with patch.object(vf, "async_playwright", lambda: FakePlaywrightCM(registry)):
            results = asyncio.run(vf.capture_and_hash(["unreachable.example"], 1))

        assert results == []
        assert len(registry) == 1, "expected exactly one page to be created"
        assert registry[0].closed, "page was not closed on the failure path (leak)"

    def test_no_pages_leak_across_many_failures(self):
        """Every page in a batch of failing domains must be closed."""
        registry = []
        domains = [f"bad{i}.example" for i in range(25)]
        with patch.object(vf, "async_playwright", lambda: FakePlaywrightCM(registry)):
            results = asyncio.run(vf.capture_and_hash(domains, 5))

        assert results == []
        assert len(registry) == 25
        leaked = [p for p in registry if not p.closed]
        assert not leaked, f"{len(leaked)} of {len(registry)} pages leaked"


class HangingPage:
    """Simulates a domain that accepts the connection then never responds."""

    def __init__(self, registry):
        self.closed = False
        registry.append(self)

    async def goto(self, url, timeout=None, wait_until=None):
        await asyncio.sleep(3600)

    async def screenshot(self, full_page=False):
        await asyncio.sleep(3600)

    async def close(self):
        self.closed = True


class HangingContext:
    def __init__(self, registry):
        self._registry = registry

    async def new_page(self):
        return HangingPage(self._registry)


class HangingBrowser:
    def __init__(self, registry):
        self._registry = registry

    async def new_context(self, **kwargs):
        return HangingContext(self._registry)

    async def close(self):
        pass


class HangingChromium:
    def __init__(self, registry):
        self._registry = registry

    async def launch(self, headless=True):
        return HangingBrowser(self._registry)


class HangingPlaywright:
    def __init__(self, registry):
        self.chromium = HangingChromium(registry)


class HangingPlaywrightCM:
    def __init__(self, registry):
        self._registry = registry

    async def __aenter__(self):
        return HangingPlaywright(self._registry)

    async def __aexit__(self, *exc):
        return False


class TestStallContainment:
    """No single domain may stall the whole batch."""

    def test_hanging_domain_is_abandoned(self):
        """A domain that never responds is dropped, not waited on forever.

        Run 32459415652 stalled 18 minutes on one domain and blew the
        step's 30-minute budget with half the batch unprocessed.
        """
        registry = []

        async def run():
            with patch.object(vf, "async_playwright", lambda: HangingPlaywrightCM(registry)):
                with patch.object(vf, "PER_DOMAIN_TIMEOUT", 0.05):
                    return await asyncio.wait_for(
                        vf.capture_and_hash(["hangs.example"], 1), timeout=5
                    )

        results = asyncio.run(run())
        assert results == []
        assert registry and registry[0].closed, "hung page was not closed"
