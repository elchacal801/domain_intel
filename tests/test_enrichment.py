
import pytest
import sys
import os
import asyncio
from unittest.mock import MagicMock, AsyncMock

# Ensure scripts directory is in path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))

# We need to mock dnspython before importing enrich_infrastructure
# because it tries to instantiate a resolver or setup environment on import (if not careful)
# or just to test logic isolation.

# Import target function
from enrich_infrastructure import process_domain

@pytest.mark.asyncio
def test_high_risk_registrar_detection():
    """
    Verify that 'nicendns.com' in NS records triggers 'HighRisk:Nicenic'
    """
    async def run():
        domain = "bad-guy.com"
        
        # Mock the resolver
        resolver_mock = AsyncMock()
        # resolve_ns returns a list of NS strings
        resolver_mock.resolve_ns.return_value = ["ns1.nicendns.com", "ns2.nicendns.com"]
        resolver_mock.resolve_mx.return_value = []
        resolver_mock.resolve_a.return_value = []
        resolver_mock.get_asn.return_value = (None, None)
        
        # Dummy semaphore
        sem = asyncio.Semaphore(1)

        # Run processing: process_domain(sem, resolver, domain)
        result = await process_domain(sem, resolver_mock, domain)
        
        assert "HighRisk:Nicenic" in result["risk_tags"]
        assert "nicendns.com" in result["nameservers"]
    
    asyncio.run(run())

@pytest.mark.asyncio
def test_benign_domain():
    """
    Verify that a benign domain (Google) does NOT trigger risk tags
    """
    async def run():
        domain = "google.com"
        
        resolver_mock = AsyncMock()
        resolver_mock.resolve_ns.return_value = ["ns1.google.com"]
        resolver_mock.resolve_mx.return_value = []
        resolver_mock.resolve_a.return_value = []
        resolver_mock.get_asn.return_value = (None, None)
        
        # Dummy semaphore
        sem = asyncio.Semaphore(1)

        # Run processing: process_domain(sem, resolver, domain)
        result = await process_domain(sem, resolver_mock, domain)
        
        # risk_tags should mark it as Unknown or empty, but definitely not HighRisk
        assert "HighRisk" not in result.get("risk_tags", "")

    asyncio.run(run())
