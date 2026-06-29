#!/usr/bin/env python3
"""
shared/otx_client.py

Centralised AlienVault OTX API helpers extracted from ``pivot_otx.py``.
Both ``pivot_otx.py`` and ``hunt_campaign.py`` import from here to avoid
duplicating the query logic.
"""

import logging
import os
import socket
from typing import List, Optional

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

OTX_API_KEY: Optional[str] = os.getenv("ALIENVAULT_OTX_API_KEY")


def resolve_target(target: str) -> Optional[str]:
    """Resolve a domain or IP string to an IP address.

    If *target* is already a valid IPv4 address it is returned as-is.
    Otherwise a DNS lookup is attempted.

    Args:
        target: A domain name or IPv4 address string.

    Returns:
        The resolved IPv4 address, or ``None`` if resolution fails.
    """
    try:
        socket.inet_aton(target)
        return target
    except socket.error:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            logger.warning("Could not resolve %s", target)
            return None


def query_otx_passive_dns(ip: str) -> List[str]:
    """Query AlienVault OTX for passive DNS records associated with an IP.

    Args:
        ip: IPv4 address to look up.

    Returns:
        A list of hostnames observed on the given IP, or an empty list on
        failure or missing API key.
    """
    if not OTX_API_KEY:
        logger.warning("ALIENVAULT_OTX_API_KEY not found in environment")
        return []

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            passive_dns = data.get("passive_dns", [])
            return [
                record.get("hostname")
                for record in passive_dns
                if record.get("hostname")
            ]
        else:
            logger.warning("OTX returned %d for %s", response.status_code, ip)
            return []
    except requests.RequestException as exc:
        logger.warning("Exception querying OTX for %s: %s", ip, exc)
        return []
