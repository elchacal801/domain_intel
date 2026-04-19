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
import subprocess
import requests
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from typing import Dict, List
from tqdm import tqdm
from shared.cymru_resolver import CymruResolver
from shared.rdap_client import RDAPClient

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
                "asn": "",
                "asn_name": "",
                "source": "mullvad_api",
                "source_date": TODAY,
                "hostname": s.get("hostname", ""),
            })

        logger.info(f"  {self.display_name}: {len(nodes)} active servers")
        return nodes


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
        seed_ips = self._load_seed()
        logger.info(f"  Seed: {len(seed_ips)} IPs from {self.seed_path}")

        rdap_confirmed = self._rdap_validate(seed_ips)
        logger.info(f"  RDAP confirmed: {len(rdap_confirmed)} IPs")

        shodan_ips = self._shodan_org_search("Astrill Systems Corp")

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


# --- Provider Registry ---

PROVIDERS: List[BaseProvider] = [
    MullvadProvider(),
    AstrillProvider(),
    NordVPNProvider(),
    ProtonVPNProvider(),
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
