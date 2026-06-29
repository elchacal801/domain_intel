# VPN Exit IP Intelligence Collection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collect VPN exit node IPs from major commercial providers (Mullvad, Astrill, NordVPN, ProtonVPN, Surfshark) and integrate them into the domain_intel enrichment pipeline for IP-level provider attribution.

**Architecture:** A single `scripts/vpn_ip_intel.py` with a provider registry pattern — each provider is a class implementing `fetch() -> list[dict]`. The orchestrator calls all providers, enriches with Team Cymru ASN data, outputs unified + per-provider CSVs. The enrichment pipeline cross-references domain A-record IPs against the combined list to add `VPN:Provider` risk tags.

**Tech Stack:** Python 3.10+, requests, shodan (free queries only), shared/cymru_resolver.py, shared/retry.py, pytest

**Spec:** `docs/plans/2026-04-19-vpn-ip-intel-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `scripts/vpn_ip_intel.py` | Create | Main script: provider registry, orchestration, CSV output |
| `scripts/shared/rdap_client.py` | Create | Lightweight RDAP lookup with caching (used by Astrill provider) |
| `tests/test_vpn_ip_intel.py` | Create | Unit tests for provider parsing and orchestration |
| `data/vpn_seeds/spur_astrill_2024.txt` | Create | Static Astrill seed list from Spur (2,403 IPs) |
| `scripts/enrich_infrastructure.py` | Modify | Add VPN IP cross-reference for risk tagging |
| `.github/workflows/update_intelligence.yml` | Modify | Add collection step after existing vpn_intel.py |
| `data/README.md` | Modify | Document new data files |

---

### Task 1: BaseProvider + MullvadProvider + CSV Output

**Files:**
- Create: `scripts/vpn_ip_intel.py`
- Test: `tests/test_vpn_ip_intel.py`

- [ ] **Step 1: Write failing tests for Mullvad provider parsing**

```python
# tests/test_vpn_ip_intel.py
#!/usr/bin/env python3
"""Tests for VPN Exit IP intelligence collection."""

import pytest
from unittest.mock import patch, MagicMock

# We'll import after creating the module
from vpn_ip_intel import MullvadProvider, BaseProvider


class TestMullvadProvider:
    """Test Mullvad API response parsing."""

    SAMPLE_API_RESPONSE = [
        {
            "hostname": "se-got-wg-001",
            "country_code": "se",
            "country_name": "Sweden",
            "city_code": "got",
            "city_name": "Gothenburg",
            "fqdn": "se-got-wg-001.relays.mullvad.net",
            "active": True,
            "owned": True,
            "provider": "31173",
            "ipv4_addr_in": "185.213.154.68",
            "ipv6_addr_in": "2a03:1b20:5:f011::a01f",
            "network_port_speed": 10,
            "stboot": True,
            "type": "wireguard",
        },
        {
            "hostname": "us-nyc-wg-301",
            "country_code": "us",
            "country_name": "USA",
            "city_code": "nyc",
            "city_name": "New York",
            "fqdn": "us-nyc-wg-301.relays.mullvad.net",
            "active": True,
            "owned": False,
            "provider": "M247",
            "ipv4_addr_in": "146.70.174.2",
            "ipv6_addr_in": None,
            "network_port_speed": 10,
            "stboot": True,
            "type": "wireguard",
        },
        {
            "hostname": "de-ber-br-001",
            "country_code": "de",
            "country_name": "Germany",
            "city_code": "ber",
            "city_name": "Berlin",
            "fqdn": "de-ber-br-001.relays.mullvad.net",
            "active": False,  # Inactive — should be excluded
            "owned": False,
            "provider": "M247",
            "ipv4_addr_in": "10.0.0.1",
            "ipv6_addr_in": None,
            "network_port_speed": 10,
            "stboot": True,
            "type": "bridge",
        },
    ]

    def test_parse_active_servers_only(self):
        provider = MullvadProvider()
        with patch("vpn_ip_intel.requests") as mock_requests:
            mock_resp = MagicMock()
            mock_resp.json.return_value = self.SAMPLE_API_RESPONSE
            mock_resp.status_code = 200
            mock_resp.raise_for_status = MagicMock()
            mock_requests.get.return_value = mock_resp

            nodes = provider.fetch()

        assert len(nodes) == 2  # Inactive server excluded
        assert nodes[0]["ip"] == "185.213.154.68"
        assert nodes[0]["provider"] == "mullvad"
        assert nodes[0]["confidence"] == "confirmed"
        assert nodes[0]["country"] == "se"
        assert nodes[0]["server_type"] == "wireguard"
        assert nodes[0]["hostname"] == "se-got-wg-001"

    def test_all_nodes_have_required_fields(self):
        provider = MullvadProvider()
        with patch("vpn_ip_intel.requests") as mock_requests:
            mock_resp = MagicMock()
            mock_resp.json.return_value = self.SAMPLE_API_RESPONSE
            mock_resp.raise_for_status = MagicMock()
            mock_requests.get.return_value = mock_resp

            nodes = provider.fetch()

        required = {"ip", "provider", "confidence", "country", "city",
                    "server_type", "source", "source_date", "hostname"}
        for node in nodes:
            assert required.issubset(node.keys()), f"Missing keys: {required - node.keys()}"

    def test_skips_entries_without_ipv4(self):
        data = [{"hostname": "test", "active": True, "ipv4_addr_in": None,
                 "country_code": "se", "city_name": "Stockholm", "type": "wireguard"}]
        provider = MullvadProvider()
        with patch("vpn_ip_intel.requests") as mock_requests:
            mock_resp = MagicMock()
            mock_resp.json.return_value = data
            mock_resp.raise_for_status = MagicMock()
            mock_requests.get.return_value = mock_resp

            nodes = provider.fetch()

        assert len(nodes) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /c/Users/anon/Documents/anon/repos/domain_intel && python -m pytest tests/test_vpn_ip_intel.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'vpn_ip_intel'`

- [ ] **Step 3: Implement BaseProvider, MullvadProvider, and CSV output**

```python
# scripts/vpn_ip_intel.py
#!/usr/bin/env python3
"""
vpn_ip_intel.py

Collects VPN exit node IPs from major commercial providers.
Each provider implements a fetch() method returning a unified schema.
Enriches with Team Cymru ASN data and outputs combined + per-provider CSVs.

Usage:
  python vpn_ip_intel.py --output data/vpn_exit_ips.csv --output-dir data/vpn_exit_ips/
"""

import argparse
import csv
import json
import logging
import os
import requests
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from typing import Dict, List
from tqdm import tqdm
from shared.cymru_resolver import CymruResolver

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

TODAY = date.today().isoformat()

FIELDS = [
    "ip", "provider", "confidence", "country", "city", "server_type",
    "asn", "asn_name", "source", "source_date", "hostname",
]


class BaseProvider(ABC):
    """Abstract base for VPN IP providers."""
    name: str = ""
    display_name: str = ""

    @abstractmethod
    def fetch(self) -> List[Dict]:
        """Returns list of VPN node dicts matching FIELDS schema."""
        raise NotImplementedError


class MullvadProvider(BaseProvider):
    """Mullvad VPN — public relay API."""
    name = "mullvad"
    display_name = "Mullvad VPN"
    API_URL = "https://api.mullvad.net/www/relays/all/"

    def fetch(self) -> List[Dict]:
        logger.info(f"Fetching {self.display_name} server list...")
        resp = requests.get(self.API_URL, timeout=30)
        resp.raise_for_status()
        servers = resp.json()

        nodes = []
        for s in servers:
            if not s.get("active") or not s.get("ipv4_addr_in"):
                continue
            nodes.append({
                "ip": s["ipv4_addr_in"],
                "provider": self.name,
                "confidence": "confirmed",
                "country": s.get("country_code", ""),
                "city": s.get("city_name", ""),
                "server_type": s.get("type", "unknown"),
                "asn": "",  # Filled by enrichment
                "asn_name": "",
                "source": "mullvad_api",
                "source_date": TODAY,
                "hostname": s.get("hostname", ""),
            })

        logger.info(f"  {self.display_name}: {len(nodes)} active servers")
        return nodes


# --- Provider Registry ---

PROVIDERS: List[BaseProvider] = [
    MullvadProvider(),
]


def enrich_asns(nodes: List[Dict], workers: int = 20) -> None:
    """Enriches nodes with ASN data via Team Cymru DNS. Mutates in place."""
    cymru = CymruResolver()
    unique_ips = list({n["ip"] for n in nodes if n["ip"] and not n["asn"]})

    if not unique_ips:
        return

    logger.info(f"Enriching {len(unique_ips)} unique IPs with ASN data...")
    ip_to_asn = {}

    def resolve(ip):
        return ip, cymru.enrich_ip(ip)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for ip, data in tqdm(executor.map(resolve, unique_ips), total=len(unique_ips), unit="ip"):
            ip_to_asn[ip] = data

    for node in nodes:
        asn_data = ip_to_asn.get(node["ip"], {})
        if asn_data:
            node["asn"] = asn_data.get("asn", "")
            node["asn_name"] = asn_data.get("name", "")
            if not node["country"] and asn_data.get("country"):
                node["country"] = asn_data["country"]


def write_csv(nodes: List[Dict], path: str) -> None:
    """Write nodes to CSV."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(nodes)
    logger.info(f"Wrote {len(nodes)} rows to {path}")


def run(output: str, output_dir: str, workers: int, providers: List[str]):
    """Main orchestration."""
    all_nodes = []

    for prov in PROVIDERS:
        if providers and prov.name not in providers:
            continue
        try:
            nodes = prov.fetch()
            all_nodes.extend(nodes)
        except Exception as e:
            logger.error(f"Provider {prov.display_name} failed: {e}")
            continue

    if not all_nodes:
        logger.warning("No VPN IPs collected from any provider.")
        return

    # Deduplicate on (ip, provider)
    seen = set()
    deduped = []
    for n in all_nodes:
        key = (n["ip"], n["provider"])
        if key not in seen:
            seen.add(key)
            deduped.append(n)
    all_nodes = deduped

    # Enrich ASNs
    enrich_asns(all_nodes, workers=workers)

    # Write combined CSV
    write_csv(all_nodes, output)

    # Write per-provider CSVs
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        by_provider = {}
        for n in all_nodes:
            by_provider.setdefault(n["provider"], []).append(n)
        for prov_name, nodes in by_provider.items():
            write_csv(nodes, os.path.join(output_dir, f"{prov_name}.csv"))

    logger.info(f"Total: {len(all_nodes)} VPN exit IPs from {len(by_provider)} providers")


def main():
    parser = argparse.ArgumentParser(description="VPN Exit IP Intelligence Collection")
    parser.add_argument("--output", default="data/vpn_exit_ips.csv", help="Combined output CSV")
    parser.add_argument("--output-dir", default="data/vpn_exit_ips", help="Per-provider output directory")
    parser.add_argument("--workers", type=int, default=20, help="Team Cymru DNS workers")
    parser.add_argument("--providers", nargs="*", default=[], help="Run specific providers only (e.g., mullvad astrill)")
    args = parser.parse_args()

    run(args.output, args.output_dir, args.workers, args.providers)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /c/Users/anon/Documents/anon/repos/domain_intel && python -m pytest tests/test_vpn_ip_intel.py -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /c/Users/anon/Documents/anon/repos/domain_intel
git add scripts/vpn_ip_intel.py tests/test_vpn_ip_intel.py
git commit -m "feat: add vpn_ip_intel.py with MullvadProvider and CSV output"
```

---

### Task 2: NordVPN and ProtonVPN Providers

**Files:**
- Modify: `scripts/vpn_ip_intel.py`
- Modify: `tests/test_vpn_ip_intel.py`

- [ ] **Step 1: Write failing tests for NordVPN and ProtonVPN parsing**

```python
# Append to tests/test_vpn_ip_intel.py

from vpn_ip_intel import NordVPNProvider, ProtonVPNProvider


class TestNordVPNProvider:
    SAMPLE_API_RESPONSE = [
        {
            "id": 1,
            "hostname": "us1234.nordvpn.com",
            "station": "198.44.136.1",
            "status": "online",
            "locations": [
                {"country": {"code": "US", "city": {"name": "New York"}}}
            ],
            "technologies": [
                {"id": 35, "name": "Wireguard"},
                {"id": 3, "name": "OpenVPN UDP"},
            ],
        },
        {
            "id": 2,
            "hostname": "de5678.nordvpn.com",
            "station": "194.233.96.2",
            "status": "offline",  # Should be excluded
            "locations": [
                {"country": {"code": "DE", "city": {"name": "Berlin"}}}
            ],
            "technologies": [{"id": 35, "name": "Wireguard"}],
        },
    ]

    def test_parse_online_servers_only(self):
        provider = NordVPNProvider()
        with patch("vpn_ip_intel.requests") as mock_requests:
            mock_resp = MagicMock()
            mock_resp.json.return_value = self.SAMPLE_API_RESPONSE
            mock_resp.raise_for_status = MagicMock()
            mock_requests.get.return_value = mock_resp

            nodes = provider.fetch()

        assert len(nodes) == 1
        assert nodes[0]["ip"] == "198.44.136.1"
        assert nodes[0]["provider"] == "nordvpn"
        assert nodes[0]["country"] == "US"
        assert nodes[0]["hostname"] == "us1234.nordvpn.com"


class TestProtonVPNProvider:
    SAMPLE_API_RESPONSE = {
        "Code": 1000,
        "LogicalServers": [
            {
                "Name": "CH#1",
                "EntryCountry": "CH",
                "ExitCountry": "CH",
                "City": "Zurich",
                "Status": 1,  # 1 = online
                "Servers": [
                    {"EntryIP": "185.159.157.1", "ExitIP": "185.159.157.2", "Status": 1}
                ],
                "Features": 0,
            },
            {
                "Name": "JP#5",
                "EntryCountry": "JP",
                "ExitCountry": "JP",
                "City": "Tokyo",
                "Status": 0,  # 0 = offline
                "Servers": [
                    {"EntryIP": "138.199.0.1", "ExitIP": "138.199.0.2", "Status": 0}
                ],
                "Features": 0,
            },
        ],
    }

    def test_parse_online_servers_only(self):
        provider = ProtonVPNProvider()
        with patch("vpn_ip_intel.requests") as mock_requests:
            mock_resp = MagicMock()
            mock_resp.json.return_value = self.SAMPLE_API_RESPONSE
            mock_resp.raise_for_status = MagicMock()
            mock_requests.get.return_value = mock_resp

            nodes = provider.fetch()

        assert len(nodes) == 1
        assert nodes[0]["ip"] == "185.159.157.2"  # Exit IP
        assert nodes[0]["provider"] == "protonvpn"
        assert nodes[0]["country"] == "CH"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /c/Users/anon/Documents/anon/repos/domain_intel && python -m pytest tests/test_vpn_ip_intel.py::TestNordVPNProvider -v`
Expected: FAIL with `ImportError`

- [ ] **Step 3: Implement NordVPN and ProtonVPN providers**

Add to `scripts/vpn_ip_intel.py`, before the `PROVIDERS` list:

```python
class NordVPNProvider(BaseProvider):
    """NordVPN — public server recommendations API."""
    name = "nordvpn"
    display_name = "NordVPN"
    API_URL = "https://api.nordvpn.com/v1/servers?limit=99999"

    def fetch(self) -> List[Dict]:
        logger.info(f"Fetching {self.display_name} server list...")
        resp = requests.get(self.API_URL, timeout=60,
                            headers={"User-Agent": "DomainIntel-VPN/1.0"})
        resp.raise_for_status()
        servers = resp.json()

        nodes = []
        for s in servers:
            ip = s.get("station")
            if not ip or s.get("status") != "online":
                continue

            country = ""
            city = ""
            locs = s.get("locations", [])
            if locs:
                country = locs[0].get("country", {}).get("code", "")
                city = locs[0].get("country", {}).get("city", {}).get("name", "")

            nodes.append({
                "ip": ip,
                "provider": self.name,
                "confidence": "confirmed",
                "country": country,
                "city": city,
                "server_type": "wireguard",
                "asn": "",
                "asn_name": "",
                "source": "nordvpn_api",
                "source_date": TODAY,
                "hostname": s.get("hostname", ""),
            })

        logger.info(f"  {self.display_name}: {len(nodes)} online servers")
        return nodes


class ProtonVPNProvider(BaseProvider):
    """ProtonVPN — public logicals API (used by open-source client)."""
    name = "protonvpn"
    display_name = "ProtonVPN"
    API_URL = "https://api.protonvpn.ch/vpn/logicals"

    def fetch(self) -> List[Dict]:
        logger.info(f"Fetching {self.display_name} server list...")
        resp = requests.get(self.API_URL, timeout=30,
                            headers={"User-Agent": "DomainIntel-VPN/1.0"})
        resp.raise_for_status()
        data = resp.json()

        nodes = []
        for logical in data.get("LogicalServers", []):
            if logical.get("Status") != 1:
                continue
            for server in logical.get("Servers", []):
                ip = server.get("ExitIP")
                if not ip or server.get("Status") != 1:
                    continue
                nodes.append({
                    "ip": ip,
                    "provider": self.name,
                    "confidence": "confirmed",
                    "country": logical.get("ExitCountry", ""),
                    "city": logical.get("City", ""),
                    "server_type": "wireguard",
                    "asn": "",
                    "asn_name": "",
                    "source": "protonvpn_api",
                    "source_date": TODAY,
                    "hostname": logical.get("Name", ""),
                })

        logger.info(f"  {self.display_name}: {len(nodes)} online servers")
        return nodes
```

Update the `PROVIDERS` list:

```python
PROVIDERS: List[BaseProvider] = [
    MullvadProvider(),
    NordVPNProvider(),
    ProtonVPNProvider(),
]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /c/Users/anon/Documents/anon/repos/domain_intel && python -m pytest tests/test_vpn_ip_intel.py -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /c/Users/anon/Documents/anon/repos/domain_intel
git add scripts/vpn_ip_intel.py tests/test_vpn_ip_intel.py
git commit -m "feat: add NordVPN and ProtonVPN providers to vpn_ip_intel.py"
```

---

### Task 3: AstrillProvider with Spur Seed + RDAP Validation

**Files:**
- Modify: `scripts/vpn_ip_intel.py`
- Create: `scripts/shared/rdap_client.py`
- Create: `data/vpn_seeds/spur_astrill_2024.txt`
- Modify: `tests/test_vpn_ip_intel.py`

- [ ] **Step 1: Create the Spur Astrill seed file**

Copy the Spur IP list into the repo:

```bash
cp /c/Users/anon/Documents/anon/career/crimsonvector/sigil/sigil-core/astrill-validation/spur_ips_raw.txt \
   /c/Users/anon/Documents/anon/repos/domain_intel/data/vpn_seeds/spur_astrill_2024.txt
```

Verify: `wc -l data/vpn_seeds/spur_astrill_2024.txt` should show 2403 lines.

- [ ] **Step 2: Create shared RDAP client**

```python
# scripts/shared/rdap_client.py
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
        """Returns RDAP registration name for the /24 block containing this IP.
        
        Returns empty string on failure.
        """
        for base_url in RDAP_URLS:
            try:
                resp = self.session.get(f"{base_url}{ip}", timeout=10, allow_redirects=True)
                if resp.status_code == 200:
                    data = resp.json()
                    name = data.get("name", "")
                    # Also check entities for registrant name
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
        
        Groups IPs by /24, checks one sample per /24, caches results.
        Returns set of IPs in confirmed Astrill blocks.
        """
        cached = self._load_cache("astrill_blocks")
        if cached is not None:
            astrill_subnets = set(cached.get("astrill_subnets", []))
            logger.info(f"RDAP cache hit: {len(astrill_subnets)} Astrill subnets")
        else:
            # Group by /24
            subnets = {}
            for ip in ips:
                parts = ip.split(".")
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                subnets.setdefault(subnet, ip)  # Keep first IP as sample

            # Only check subnets with 3+ IPs (worth the lookup)
            subnet_counts = {}
            for ip in ips:
                parts = ip.split(".")
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1

            to_check = {s: subnets[s] for s in subnets
                        if subnet_counts.get(s, 0) >= 3}

            logger.info(f"Checking RDAP for {len(to_check)} subnets (3+ IPs each)...")
            astrill_subnets = set()
            for subnet, sample_ip in to_check.items():
                name = self.check_block_owner(sample_ip)
                if "astrill" in name.lower():
                    astrill_subnets.add(subnet)
                time.sleep(0.3)  # Rate limit

            self._save_cache("astrill_blocks", {
                "astrill_subnets": list(astrill_subnets)
            })
            logger.info(f"RDAP: {len(astrill_subnets)} Astrill-registered subnets")

        # Map back to IPs
        confirmed = set()
        for ip in ips:
            parts = ip.split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            if subnet in astrill_subnets:
                confirmed.add(ip)

        return confirmed
```

- [ ] **Step 3: Write failing tests for AstrillProvider**

```python
# Append to tests/test_vpn_ip_intel.py

from vpn_ip_intel import AstrillProvider


class TestAstrillProvider:
    def test_load_seed_file(self, tmp_path):
        seed = tmp_path / "seed.txt"
        seed.write_text("1.2.3.4\n5.6.7.8\n\n9.10.11.12\n")

        provider = AstrillProvider(seed_path=str(seed))
        with patch.object(provider, "_rdap_validate", return_value={"1.2.3.4"}), \
             patch.object(provider, "_shodan_org_search", return_value={"99.99.99.99"}):
            nodes = provider.fetch()

        # 3 from seed + 1 from Shodan
        assert len(nodes) == 4
        confirmed = [n for n in nodes if n["confidence"] == "confirmed"]
        assert len(confirmed) == 1
        assert confirmed[0]["ip"] == "1.2.3.4"

    def test_shodan_new_ips_added(self, tmp_path):
        seed = tmp_path / "seed.txt"
        seed.write_text("1.1.1.1\n")

        provider = AstrillProvider(seed_path=str(seed))
        with patch.object(provider, "_rdap_validate", return_value=set()), \
             patch.object(provider, "_shodan_org_search", return_value={"2.2.2.2", "3.3.3.3"}):
            nodes = provider.fetch()

        ips = {n["ip"] for n in nodes}
        assert "2.2.2.2" in ips
        assert "3.3.3.3" in ips
        shodan_nodes = [n for n in nodes if n["source"] == "shodan_org"]
        assert len(shodan_nodes) == 2
        assert all(n["confidence"] == "high" for n in shodan_nodes)
```

- [ ] **Step 4: Implement AstrillProvider**

Add to `scripts/vpn_ip_intel.py`:

```python
import subprocess
from shared.rdap_client import RDAPClient


class AstrillProvider(BaseProvider):
    """Astrill VPN — Spur seed list + RDAP validation + Shodan org search."""
    name = "astrill"
    display_name = "Astrill VPN"
    DEFAULT_SEED = "data/vpn_seeds/spur_astrill_2024.txt"

    def __init__(self, seed_path: str = None):
        self.seed_path = seed_path or self.DEFAULT_SEED
        self.rdap = RDAPClient()

    def _load_seed(self) -> list:
        if not os.path.exists(self.seed_path):
            logger.warning(f"Astrill seed not found: {self.seed_path}")
            return []
        with open(self.seed_path) as f:
            return [line.strip() for line in f if line.strip()]

    def _rdap_validate(self, ips: list) -> set:
        return self.rdap.validate_astrill_blocks(ips)

    def _shodan_org_search(self, org_name: str) -> set:
        """Use Shodan CLI search (free query) to find IPs attributed to an org."""
        try:
            result = subprocess.run(
                ["shodan", "search", "--fields", "ip_str",
                 f'org:"{org_name}"', "--limit", "1000"],
                capture_output=True, text=True, timeout=60
            )
            ips = set()
            for line in result.stdout.splitlines():
                ip = line.strip().split("\t")[0] if "\t" in line else line.strip()
                if ip and ip[0].isdigit():
                    ips.add(ip)
            logger.info(f"  Shodan org:{org_name}: {len(ips)} IPs")
            return ips
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning(f"Shodan CLI not available or timed out: {e}")
            return set()

    def fetch(self) -> List[Dict]:
        logger.info(f"Fetching {self.display_name} IPs...")

        # 1. Load seed
        seed_ips = self._load_seed()
        logger.info(f"  Seed: {len(seed_ips)} IPs from {self.seed_path}")

        # 2. RDAP validation
        rdap_confirmed = self._rdap_validate(seed_ips)
        logger.info(f"  RDAP confirmed: {len(rdap_confirmed)} IPs")

        # 3. Shodan org search
        shodan_ips = self._shodan_org_search("Astrill Systems Corp")

        # 4. Build nodes
        nodes = []
        seed_set = set(seed_ips)

        for ip in seed_ips:
            confidence = "confirmed" if ip in rdap_confirmed else "medium"
            nodes.append({
                "ip": ip,
                "provider": self.name,
                "confidence": confidence,
                "country": "",
                "city": "",
                "server_type": "exit",
                "asn": "",
                "asn_name": "",
                "source": "spur_2024+rdap" if ip in rdap_confirmed else "spur_2024",
                "source_date": TODAY,
                "hostname": "",
            })

        # Add Shodan-only IPs
        for ip in shodan_ips - seed_set:
            nodes.append({
                "ip": ip,
                "provider": self.name,
                "confidence": "high",
                "country": "",
                "city": "",
                "server_type": "exit",
                "asn": "",
                "asn_name": "",
                "source": "shodan_org",
                "source_date": TODAY,
                "hostname": "",
            })

        logger.info(f"  {self.display_name}: {len(nodes)} total IPs")
        return nodes
```

Update `PROVIDERS`:

```python
PROVIDERS: List[BaseProvider] = [
    MullvadProvider(),
    AstrillProvider(),
    NordVPNProvider(),
    ProtonVPNProvider(),
]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /c/Users/anon/Documents/anon/repos/domain_intel && python -m pytest tests/test_vpn_ip_intel.py -v`
Expected: All 8 tests PASS

- [ ] **Step 6: Commit**

```bash
cd /c/Users/anon/Documents/anon/repos/domain_intel
git add scripts/vpn_ip_intel.py scripts/shared/rdap_client.py \
       data/vpn_seeds/spur_astrill_2024.txt tests/test_vpn_ip_intel.py
git commit -m "feat: add AstrillProvider with Spur seed, RDAP validation, Shodan org search"
```

---

### Task 4: Enrichment Pipeline Integration (risk tagging)

**Files:**
- Modify: `scripts/enrich_infrastructure.py:120-180`
- Modify: `tests/test_vpn_ip_intel.py`

- [ ] **Step 1: Write failing test for VPN risk tagging**

```python
# Append to tests/test_vpn_ip_intel.py

from vpn_ip_intel import load_vpn_lookup


class TestVPNRiskTagging:
    def test_load_vpn_lookup(self, tmp_path):
        csv_path = tmp_path / "vpn_exit_ips.csv"
        csv_path.write_text(
            "ip,provider,confidence,country,city,server_type,asn,asn_name,source,source_date,hostname\n"
            "1.2.3.4,mullvad,confirmed,se,Gothenburg,wireguard,AS39351,ESAB,mullvad_api,2026-04-19,se-got-wg-001\n"
            "5.6.7.8,astrill,medium,us,,exit,AS62240,Clouvider,spur_2024,2026-04-19,\n"
        )
        lookup = load_vpn_lookup(str(csv_path))
        assert "1.2.3.4" in lookup
        assert lookup["1.2.3.4"]["provider"] == "mullvad"
        assert "5.6.7.8" in lookup
        assert lookup["5.6.7.8"]["provider"] == "astrill"
        assert "9.9.9.9" not in lookup

    def test_risk_tag_format(self, tmp_path):
        csv_path = tmp_path / "vpn_exit_ips.csv"
        csv_path.write_text(
            "ip,provider,confidence,country,city,server_type,asn,asn_name,source,source_date,hostname\n"
            "1.2.3.4,mullvad,confirmed,se,Gothenburg,wireguard,AS39351,ESAB,mullvad_api,2026-04-19,\n"
        )
        lookup = load_vpn_lookup(str(csv_path))
        tag = f"VPN:{lookup['1.2.3.4']['provider'].title()}"
        assert tag == "VPN:Mullvad"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /c/Users/anon/Documents/anon/repos/domain_intel && python -m pytest tests/test_vpn_ip_intel.py::TestVPNRiskTagging -v`
Expected: FAIL with `ImportError: cannot import name 'load_vpn_lookup'`

- [ ] **Step 3: Add load_vpn_lookup to vpn_ip_intel.py**

Add to `scripts/vpn_ip_intel.py`:

```python
def load_vpn_lookup(csv_path: str = "data/vpn_exit_ips.csv") -> Dict[str, Dict]:
    """Load VPN exit IPs into a lookup dict keyed by IP address.
    
    Used by enrich_infrastructure.py to add VPN:Provider risk tags.
    Returns empty dict if file doesn't exist.
    """
    if not os.path.exists(csv_path):
        return {}
    lookup = {}
    with open(csv_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            lookup[row["ip"]] = row
    return lookup
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /c/Users/anon/Documents/anon/repos/domain_intel && python -m pytest tests/test_vpn_ip_intel.py::TestVPNRiskTagging -v`
Expected: 2 tests PASS

- [ ] **Step 5: Modify enrich_infrastructure.py to use VPN lookup**

In `scripts/enrich_infrastructure.py`, add the import at the top:

```python
from vpn_ip_intel import load_vpn_lookup
```

In the `main()` or top-level execution area where enrichment begins, load the lookup:

```python
# Load VPN exit IP lookup for risk tagging
vpn_lookup = load_vpn_lookup()
logger.info(f"Loaded {len(vpn_lookup)} VPN exit IPs for risk tagging")
```

In the `enrich_domain()` function (around line 148-155), after resolving the A record and ASN, add VPN tagging:

```python
            # After a_record ASN resolution (around line 155):
            if a_ip:
                result["a_record"] = a_ip
                a_asn_data = await resolver.resolve_asn(a_ip)
                a_asn = a_asn_data.get("asn", "")
                if a_asn:
                    result["a_record_asn"] = a_asn
                    result["a_record_asn_name"] = await resolver.resolve_asn_name(a_asn)
                
                # VPN exit node tagging
                if a_ip in vpn_lookup:
                    vpn_tag = f"VPN:{vpn_lookup[a_ip]['provider'].title()}"
                    existing = result.get("risk_tags", "")
                    result["risk_tags"] = f"{existing};{vpn_tag}" if existing else vpn_tag
```

Note: The `vpn_lookup` dict needs to be accessible inside the async function. Pass it as a parameter to the enrichment coroutine or load it as a module-level variable. Follow the pattern already used for the Nicenic risk tag check (module-level constant).

- [ ] **Step 6: Commit**

```bash
cd /c/Users/anon/Documents/anon/repos/domain_intel
git add scripts/vpn_ip_intel.py scripts/enrich_infrastructure.py tests/test_vpn_ip_intel.py
git commit -m "feat: integrate VPN exit IP tagging into enrichment pipeline"
```

---

### Task 5: GitHub Actions Integration + Documentation

**Files:**
- Modify: `.github/workflows/update_intelligence.yml:214-218`
- Modify: `data/README.md`

- [ ] **Step 1: Add VPN IP collection step to workflow**

In `.github/workflows/update_intelligence.yml`, modify the "Infrastructure Intel" step (lines 214-218):

```yaml
      - name: Infrastructure Intel (ASN/VPN/Tor)
        run: |
          python scripts/asn_intel.py
          python scripts/vpn_intel.py
          python scripts/tor_intel.py
          python scripts/vpn_ip_intel.py
        continue-on-error: true
```

Adding `continue-on-error: true` ensures a failed VPN IP collection (e.g., API down) doesn't block the rest of the pipeline.

- [ ] **Step 2: Update data/README.md**

Add to the appropriate section of `data/README.md`:

```markdown
### VPN Exit IP Intelligence

| File | Description |
|------|-------------|
| `vpn_exit_ips.csv` | Combined VPN exit node IPs from all providers. Columns: ip, provider, confidence, country, city, server_type, asn, asn_name, source, source_date, hostname |
| `vpn_exit_ips/mullvad.csv` | Mullvad VPN servers (from public API) |
| `vpn_exit_ips/astrill.csv` | Astrill VPN IPs (Spur seed + RDAP validation + Shodan org) |
| `vpn_exit_ips/nordvpn.csv` | NordVPN servers (from public API) |
| `vpn_exit_ips/protonvpn.csv` | ProtonVPN servers (from public API) |
| `vpn_seeds/spur_astrill_2024.txt` | Static Astrill IP seed list from Spur (published 2024-12-19) |

**Confidence levels:**
- `confirmed`: IP is in a block registered to the VPN provider (RDAP) or comes from the provider's own API
- `high`: IP attributed to the provider by Shodan org search
- `medium`: IP in the Spur seed list but not in a confirmed RDAP block
- `low`: Static/community-sourced, unvalidated
```

- [ ] **Step 3: Commit**

```bash
cd /c/Users/anon/Documents/anon/repos/domain_intel
git add .github/workflows/update_intelligence.yml data/README.md
git commit -m "feat: add VPN IP collection to daily pipeline, update data docs"
```

---

### Task 6: Local End-to-End Verification

- [ ] **Step 1: Run full test suite**

```bash
cd /c/Users/anon/Documents/anon/repos/domain_intel
python -m pytest tests/test_vpn_ip_intel.py -v
```

Expected: All tests pass.

- [ ] **Step 2: Run vpn_ip_intel.py with Mullvad only (fastest)**

```bash
cd /c/Users/anon/Documents/anon/repos/domain_intel
python scripts/vpn_ip_intel.py --providers mullvad --workers 10
```

Expected output:
- `data/vpn_exit_ips.csv` with ~550+ rows
- `data/vpn_exit_ips/mullvad.csv` with same
- All rows have `asn` and `asn_name` populated

- [ ] **Step 3: Spot-check CSV output**

```bash
head -5 data/vpn_exit_ips.csv
wc -l data/vpn_exit_ips.csv
```

Verify: Header matches FIELDS, IPs look valid, ASN data populated.

- [ ] **Step 4: Run with all available providers**

```bash
python scripts/vpn_ip_intel.py --workers 20
```

Expected: ~10K+ rows in `data/vpn_exit_ips.csv` across 3-4 providers (Mullvad + NordVPN + ProtonVPN + Astrill if Shodan CLI available).

- [ ] **Step 5: Final commit**

```bash
cd /c/Users/anon/Documents/anon/repos/domain_intel
git add -A
git commit -m "docs: add vpn-ip-intel design spec and implementation plan"
```
