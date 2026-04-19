#!/usr/bin/env python3
"""
shared/rdap_client.py

Lightweight RDAP client for IP block ownership lookups.
Caches results to JSON with configurable TTL.
"""

import json
import logging
import os
import time
import requests
from typing import Dict, Optional

logger = logging.getLogger(__name__)

RDAP_URLS = [
    "https://rdap.arin.net/registry/ip/",
    "https://rdap.db.ripe.net/ip/",
]

DEFAULT_CACHE_DIR = "data/.vpn_cache"
DEFAULT_TTL_DAYS = 30


class RDAPClient:
    """Checks IP block ownership via RDAP with local JSON cache."""

    def __init__(self, cache_dir: str = DEFAULT_CACHE_DIR, ttl_days: int = DEFAULT_TTL_DAYS):
        self.cache_dir = cache_dir
        self.ttl_seconds = ttl_days * 86400
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "DomainIntel-RDAP/1.0"})
        os.makedirs(cache_dir, exist_ok=True)

    def _cache_path(self, label: str) -> str:
        return os.path.join(self.cache_dir, f"rdap_{label}.json")

    def _load_cache(self, label: str) -> Optional[Dict]:
        path = self._cache_path(label)
        if not os.path.exists(path):
            return None
        try:
            with open(path) as f:
                data = json.load(f)
            if time.time() - data.get("_cached_at", 0) < self.ttl_seconds:
                return data.get("results", {})
        except (json.JSONDecodeError, KeyError):
            pass
        return None

    def _save_cache(self, label: str, results: Dict) -> None:
        path = self._cache_path(label)
        with open(path, "w") as f:
            json.dump({"_cached_at": time.time(), "results": results}, f)

    def check_block_owner(self, ip: str) -> str:
        """Returns RDAP registration name for the IP block.
        Returns empty string on failure.
        """
        for base_url in RDAP_URLS:
            try:
                resp = self.session.get(f"{base_url}{ip}", timeout=10, allow_redirects=True)
                if resp.status_code == 200:
                    data = resp.json()
                    name = data.get("name", "")
                    for ent in data.get("entities", []):
                        vcard = ent.get("vcardArray", [None, []])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn" and "astrill" in str(item[3]).lower():
                                    return f"ASTRILL ({name})"
                    if "astrill" in name.lower():
                        return name
                    return name
            except Exception as e:
                logger.debug(f"RDAP lookup failed for {ip} at {base_url}: {e}")
                continue
        return ""

    def validate_astrill_blocks(self, ips: list) -> set:
        """Check which IPs are in RDAP blocks registered to Astrill.
        Groups by /24, checks one sample per /24, caches results.
        Returns set of IPs in confirmed Astrill blocks.
        """
        cached = self._load_cache("astrill_blocks")
        if cached is not None:
            astrill_subnets = set(cached.get("astrill_subnets", []))
            logger.info(f"RDAP cache hit: {len(astrill_subnets)} Astrill subnets")
        else:
            subnets = {}
            for ip in ips:
                parts = ip.split(".")
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                subnets.setdefault(subnet, ip)

            subnet_counts = {}
            for ip in ips:
                parts = ip.split(".")
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1

            to_check = {s: subnets[s] for s in subnets if subnet_counts.get(s, 0) >= 3}

            logger.info(f"Checking RDAP for {len(to_check)} subnets (3+ IPs each)...")
            astrill_subnets = set()
            for subnet, sample_ip in to_check.items():
                name = self.check_block_owner(sample_ip)
                if "astrill" in name.lower():
                    astrill_subnets.add(subnet)
                time.sleep(0.3)

            self._save_cache("astrill_blocks", {"astrill_subnets": list(astrill_subnets)})
            logger.info(f"RDAP: {len(astrill_subnets)} Astrill-registered subnets")

        confirmed = set()
        for ip in ips:
            parts = ip.split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            if subnet in astrill_subnets:
                confirmed.add(ip)

        return confirmed
