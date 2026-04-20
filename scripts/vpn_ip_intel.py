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


class SurfsharkProvider(BaseProvider):
    """Surfshark — public cluster API + DNS resolution."""
    name = "surfshark"
    display_name = "Surfshark"
    API_URL = "https://api.surfshark.com/v4/server/clusters"

    def fetch(self) -> List[Dict]:
        import subprocess as _sp

        logger.info(f"Fetching {self.display_name} cluster list...")
        resp = requests.get(self.API_URL, timeout=30,
                            headers={"User-Agent": "DomainIntel-VPN/1.0"})
        resp.raise_for_status()
        clusters = resp.json()

        logger.info(f"  {len(clusters)} clusters, resolving hostnames via DNS...")
        nodes = []
        seen_ips = set()

        for cluster in clusters:
            hostname = cluster.get("connectionName", "")
            if not hostname:
                continue
            cc = cluster.get("countryCode", "")
            city = cluster.get("location", "")

            # Resolve hostname to IPs
            try:
                result = _sp.run(
                    ["dig", "+short", hostname],
                    capture_output=True, text=True, timeout=5
                )
                ips = [ip.strip() for ip in result.stdout.strip().split("\n")
                       if ip.strip() and ip.strip()[0].isdigit()]
            except Exception:
                ips = []

            for ip in ips:
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)
                nodes.append({
                    "ip": ip,
                    "provider": self.name,
                    "confidence": "confirmed",
                    "country": cc,
                    "city": city,
                    "server_type": "wireguard",
                    "asn": "",
                    "asn_name": "",
                    "source": "surfshark_api+dns",
                    "source_date": TODAY,
                    "hostname": hostname,
                })

        logger.info(f"  {self.display_name}: {len(nodes)} IPs from {len(clusters)} clusters")
        return nodes


class DNSEnumProvider(BaseProvider):
    """Base class for providers enumerated via DNS hostname resolution.

    Subclasses define hostname patterns and country lists. This base handles
    the DNS resolution and deduplication.
    """
    name = ""
    display_name = ""
    # List of (hostname_template, country_code) tuples
    # Template uses {n:03d} for numbered servers, {cc} for country codes
    _hostnames: List[tuple] = []

    def _generate_hostnames(self) -> List[tuple]:
        """Override to generate (hostname, country_code) pairs."""
        return self._hostnames

    def fetch(self) -> List[Dict]:
        import subprocess as _sp

        hostnames = self._generate_hostnames()
        if not hostnames:
            logger.warning(f"{self.display_name}: no hostnames to resolve")
            return []

        logger.info(f"Resolving {len(hostnames)} {self.display_name} hostnames via DNS...")
        nodes = []
        seen_ips = set()

        for hostname, cc in hostnames:
            try:
                r = _sp.run(["dig", "+short", hostname],
                            capture_output=True, text=True, timeout=3)
                ips = [ip.strip() for ip in r.stdout.strip().split("\n")
                       if ip.strip() and ip.strip()[0].isdigit()]
            except Exception:
                ips = []

            for ip in ips:
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)
                nodes.append({
                    "ip": ip,
                    "provider": self.name,
                    "confidence": "confirmed",
                    "country": cc.upper() if cc else "",
                    "city": "",
                    "server_type": "wireguard",
                    "asn": "",
                    "asn_name": "",
                    "source": f"{self.name}_dns",
                    "source_date": TODAY,
                    "hostname": hostname,
                })

        logger.info(f"  {self.display_name}: {len(nodes)} IPs")
        return nodes


class PIAProvider(BaseProvider):
    """Private Internet Access — public server list API."""
    name = "pia"
    display_name = "Private Internet Access"
    API_URL = "https://serverlist.piaservers.net/vpninfo/servers/v6"

    def fetch(self) -> List[Dict]:
        logger.info(f"Fetching {self.display_name} server list...")
        resp = requests.get(self.API_URL, timeout=30)
        resp.raise_for_status()

        # Response is JSON on first line + RSA signature on remaining lines
        first_line = resp.text.split("\n")[0]
        import json as _json
        data = _json.loads(first_line)

        nodes = []
        seen_ips = set()
        for region in data.get("regions", []):
            if region.get("offline"):
                continue
            cc = region.get("country", "")
            name = region.get("name", "")
            for proto, server_list in region.get("servers", {}).items():
                for s in server_list:
                    ip = s.get("ip")
                    if not ip or ip in seen_ips:
                        continue
                    seen_ips.add(ip)
                    nodes.append({
                        "ip": ip,
                        "provider": self.name,
                        "confidence": "confirmed",
                        "country": cc,
                        "city": name,
                        "server_type": proto,
                        "asn": "",
                        "asn_name": "",
                        "source": "pia_api",
                        "source_date": TODAY,
                        "hostname": s.get("cn", ""),
                    })

        logger.info(f"  {self.display_name}: {len(nodes)} IPs from {len(data.get('regions', []))} regions")
        return nodes


class CyberGhostProvider(DNSEnumProvider):
    """CyberGhost — DNS enumeration of N-CC.cg-dialup.net hostnames."""
    name = "cyberghost"
    display_name = "CyberGhost"

    COUNTRIES = [
        "us", "de", "uk", "gb", "fr", "nl", "ro", "ca", "au", "jp", "se", "ch", "at",
        "no", "dk", "fi", "es", "it", "pt", "pl", "cz", "be", "hu", "bg", "hr", "ie",
        "lu", "lv", "lt", "ee", "sg", "hk", "kr", "in", "br", "mx", "ar", "cl", "co",
        "za", "il", "tr", "ua", "ru", "kz", "th", "vn", "my", "ph", "id", "nz", "tw",
        "cn", "pk", "ng", "ke", "eg", "ma", "al", "ba", "cy", "ge", "gr", "is", "md",
        "me", "mk", "mt", "rs", "si", "sk", "pa", "cr", "py", "uy", "ve", "pe", "ec", "do",
    ]

    def _generate_hostnames(self):
        pairs = []
        for cc in self.COUNTRIES:
            for n in range(1, 51):
                pairs.append((f"{n}-{cc}.cg-dialup.net", cc))
        return pairs


class TorGuardProvider(DNSEnumProvider):
    """TorGuard — DNS enumeration of CC.torguard.org and CC.secureconnect.me."""
    name = "torguard"
    display_name = "TorGuard"

    COUNTRIES = [
        "us", "uk", "ca", "au", "de", "fr", "nl", "se", "ch", "no", "dk", "fi", "es",
        "it", "pt", "pl", "cz", "at", "be", "hu", "bg", "ro", "hr", "ie", "lu", "lv",
        "lt", "ee", "sg", "hk", "jp", "kr", "in", "br", "mx", "ar", "za", "il", "tr",
        "ua", "ru", "nz", "th", "vn", "my", "ph", "id", "tw", "gr", "is", "cy", "pa", "cr",
    ]
    US_CITIES = ["ny", "la", "chi", "dal", "mia", "atl", "sea", "den", "lv", "sf", "dc"]

    def _generate_hostnames(self):
        pairs = []
        for cc in self.COUNTRIES:
            pairs.append((f"{cc}.torguard.org", cc))
            pairs.append((f"{cc}.secureconnect.me", cc))
        for city in self.US_CITIES:
            pairs.append((f"us-{city}.torguard.org", "us"))
            pairs.append((f"us-{city}.secureconnect.me", "us"))
        return pairs


class WindscribeProvider(DNSEnumProvider):
    """Windscribe — DNS enumeration of REGION-NNN.windscribe.com hostnames."""
    name = "windscribe"
    display_name = "Windscribe"

    REGIONS = {
        "us-east": 60, "us-central": 35, "us-west": 20,
        "ca": 20, "ca-west": 10,
        "uk": 55, "fr": 10, "de": 10, "nl": 10, "se": 10,
        "no": 5, "dk": 5, "fi": 5, "ch": 5, "es": 5, "it": 5, "pt": 5,
        "ie": 5, "ro": 5, "bg": 5, "pl": 5, "cz": 5, "gr": 5, "tr": 5,
        "ru": 10, "ua": 5, "md": 5, "ee": 5, "lv": 5, "hr": 5, "lu": 5,
        "jp": 5, "sg": 10, "au": 10, "nz": 5, "hk": 5, "in": 5,
        "br": 5, "za": 5, "ar": 5, "my": 5, "th": 5, "vn": 5, "tw": 5, "id": 5,
    }

    def _generate_hostnames(self):
        pairs = []
        for region, max_n in self.REGIONS.items():
            cc = region.split("-")[0]  # us-east -> us
            for n in range(1, max_n + 1):
                pairs.append((f"{region}-{n:03d}.windscribe.com", cc))
        return pairs


class ProtonVPNProvider(BaseProvider):
    """ProtonVPN — reads server list from local ProtonVPN client cache.

    The ProtonVPN Windows/Linux client stores its server list as a protobuf
    binary in local app storage. This provider reads that cache directly,
    avoiding the need for API authentication (which requires SRP auth).

    Falls back to a static seed file if the local cache isn't found.
    The cache is refreshed automatically by the ProtonVPN client app.

    Cache location (Windows):
        %LOCALAPPDATA%/Proton/Proton VPN/Storage/Servers.*.bin
    """
    name = "protonvpn"
    display_name = "ProtonVPN"

    def __init__(self, cache_path: str = None):
        self.cache_path = cache_path

    def _find_cache(self) -> str:
        """Find the ProtonVPN Servers.*.bin cache file."""
        if self.cache_path and os.path.exists(self.cache_path):
            return self.cache_path

        # Windows: %LOCALAPPDATA%/Proton/Proton VPN/Storage/
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        if local_appdata:
            storage_dir = os.path.join(local_appdata, "Proton", "Proton VPN", "Storage")
            if os.path.isdir(storage_dir):
                import glob
                matches = glob.glob(os.path.join(storage_dir, "Servers.*.bin"))
                if matches:
                    return matches[0]

        # Linux: ~/.local/share/protonvpn/ (varies by client)
        home = os.path.expanduser("~")
        for candidate in [
            os.path.join(home, ".local", "share", "protonvpn"),
            os.path.join(home, ".config", "protonvpn"),
        ]:
            if os.path.isdir(candidate):
                import glob
                matches = glob.glob(os.path.join(candidate, "**/Servers.*.bin"), recursive=True)
                if matches:
                    return matches[0]

        return ""

    def _parse_cache(self, path: str) -> List[Dict]:
        """Parse IPs and hostnames from protobuf binary cache."""
        import re

        with open(path, "rb") as f:
            data = f.read()

        # Pattern: IP followed by node-XX-NN.protonvpn.net hostname
        ip_host_pattern = re.compile(
            rb"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\x00{0,2}.{0,4}"
            rb"(node-[a-z]{2}-\d+\.protonvpn\.net)"
        )
        all_ip_pattern = re.compile(rb"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

        nodes = []
        seen_ips = set()

        # First pass: IPs with hostnames
        for match in ip_host_pattern.finditer(data):
            ip = match.group(1).decode()
            hostname = match.group(2).decode()
            parts = ip.split(".")
            if not all(0 <= int(p) <= 255 for p in parts):
                continue
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            country = hostname.split("-")[1].upper()
            nodes.append({
                "ip": ip,
                "provider": self.name,
                "confidence": "confirmed",
                "country": country,
                "city": "",
                "server_type": "wireguard",
                "asn": "",
                "asn_name": "",
                "source": "protonvpn_local_cache",
                "source_date": TODAY,
                "hostname": hostname,
            })

        # Second pass: IPs without hostnames
        for match in all_ip_pattern.finditer(data):
            ip = match.group(1).decode()
            parts = ip.split(".")
            if not all(0 <= int(p) <= 255 for p in parts):
                continue
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            nodes.append({
                "ip": ip,
                "provider": self.name,
                "confidence": "confirmed",
                "country": "",
                "city": "",
                "server_type": "wireguard",
                "asn": "",
                "asn_name": "",
                "source": "protonvpn_local_cache",
                "source_date": TODAY,
                "hostname": "",
            })

        return nodes

    def fetch(self) -> List[Dict]:
        cache = self._find_cache()
        if not cache:
            logger.info(f"Skipping {self.display_name}: no local client cache found "
                        f"(install ProtonVPN client or set cache path)")
            return []

        logger.info(f"Reading {self.display_name} server list from local cache: {cache}")
        nodes = self._parse_cache(cache)
        logger.info(f"  {self.display_name}: {len(nodes)} servers ({sum(1 for n in nodes if n['hostname'])} with hostnames)")
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
    NordVPNProvider(),
    PIAProvider(),
    SurfsharkProvider(),
    ProtonVPNProvider(),
    AstrillProvider(),
    CyberGhostProvider(),
    TorGuardProvider(),
    WindscribeProvider(),
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
