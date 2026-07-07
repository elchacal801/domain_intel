#!/usr/bin/env python3
"""
vpn_ip_intel.py

Collects VPN relay IPs from major commercial providers.
Each provider implements a fetch() method returning a unified schema with ip_role tagging.
Enriches with Team Cymru ASN data, infers /24 prefix blocks, and outputs combined + per-provider CSVs.

Usage:
  python vpn_ip_intel.py --output data/vpn_relay_ips.csv --output-dir data/vpn_exit_ips/
"""

import argparse
import csv
import ipaddress
import json
import logging
import os
import re
import subprocess
import requests
from abc import ABC, abstractmethod
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime
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
    "collection_method", "threat_relevance", "ip_role", "prefix",
    "score_prehire", "tier_prehire", "score_posthire", "tier_posthire",
    "indicator_id",
    "first_seen", "last_seen", "active",
]

# Lean projection of FIELDS for the LogScale lookup file (data/vpn_relay_lookup.csv).
# Each row keys on `ip` (exact) or `prefix` (CIDR) — never both.
LOOKUP_FIELDS = [
    "ip", "prefix", "provider", "asn", "asn_name", "source_date",
    "score_prehire", "tier_prehire", "score_posthire", "tier_posthire",
    "first_seen", "last_seen", "active",
]

# Warn when the lookup approaches LogScale's 10 MB upload limit.
LOOKUP_WARN_BYTES = 9_000_000

IP_ROLES = {"ingress", "egress", "prefix-inferred", "egress-inferred", "unknown"}

SHARED_HOSTING_ASNS = {
    "AS16509",   # AWS
    "AS8075",    # Microsoft/Azure
    "AS15169",   # Google Cloud
    "AS14061",   # DigitalOcean
    "AS20473",   # Vultr
    "AS63949",   # Linode/Akamai
    "AS13335",   # Cloudflare
    "AS36351",   # SoftLayer/IBM
}

_COUNTRY_ALIASES = {"UK": "GB"}
_SERVER_TYPE_ALIASES = {"wg": "wireguard", "openvpn_udp": "openvpn", "openvpn_tcp": "openvpn"}
_VALID_CONFIDENCES = {"confirmed", "high", "medium", "low"}


def normalize_node(node: dict) -> dict:
    """Idempotent canonical normalization of a VPN node dict. Mutates in place."""
    cc = node.get("country", "").upper()
    node["country"] = _COUNTRY_ALIASES.get(cc, cc)
    st = node.get("server_type", "").lower()
    node["server_type"] = _SERVER_TYPE_ALIASES.get(st, st)
    node["hostname"] = node.get("hostname", "").lower()
    conf = node.get("confidence", "").lower()
    node["confidence"] = conf if conf in _VALID_CONFIDENCES else "low"
    node.setdefault("ip_role", "unknown")
    node.setdefault("prefix", "")
    return node


class BaseProvider(ABC):
    """Abstract base for VPN IP providers."""
    name: str = ""
    display_name: str = ""
    collection_method: str = ""
    threat_relevance: str = ""

    @abstractmethod
    def fetch(self) -> List[Dict]:
        """Returns list of VPN node dicts matching FIELDS schema."""
        raise NotImplementedError

    @staticmethod
    def shodan_org_search(org_name: str) -> set:
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


class MullvadProvider(BaseProvider):
    """Mullvad VPN — public relay API."""
    name = "mullvad"
    display_name = "Mullvad VPN"
    collection_method = "Public API"
    threat_relevance = "Verified no-logs (2023 Swedish police raid); privacy-focused"
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
                "ip_role": "ingress",
                "prefix": "",
            })

        logger.info(f"  {self.display_name}: {len(nodes)} active ingress servers")

        # Merge exit IPs from probe seed file
        egress_nodes = self.load_exit_seeds()
        nodes.extend(egress_nodes)

        return nodes

    SEED_PATH = os.path.join(
        os.path.dirname(__file__), "..", "data", "vpn_seeds", "mullvad_exit_ips.csv"
    )

    def load_exit_seeds(self) -> List[Dict]:
        """Load exit IPs from SOCKS5 probe seed CSV if present."""
        if not os.path.exists(self.SEED_PATH):
            logger.info("  No Mullvad exit seed file found; skipping egress IPs")
            return []

        nodes = []
        with open(self.SEED_PATH, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                exit_ip = row.get("exit_ip", "").strip()
                if not exit_ip:
                    continue
                nodes.append({
                    "ip": exit_ip,
                    "provider": self.name,
                    "confidence": "confirmed",
                    "country": "",
                    "city": "",
                    "server_type": "exit",
                    "asn": "",
                    "asn_name": "",
                    "source": "socks5_probe",
                    "source_date": row.get("probe_date", TODAY),
                    "hostname": row.get("relay_hostname", ""),
                    "ip_role": "egress",
                    "prefix": "",
                })

        logger.info(f"  {self.display_name} exit seeds: {len(nodes)} egress IPs")
        return nodes


class NordVPNProvider(BaseProvider):
    """NordVPN — public server recommendations API."""
    name = "nordvpn"
    display_name = "NordVPN"
    collection_method = "Public API"
    threat_relevance = "DPRK confirmed (Mandiant: UNC4899 JumpCloud attack, secondary VPN)"
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
                "ip_role": "unknown",
                "prefix": "",
            })
        logger.info(f"  {self.display_name}: {len(nodes)} online servers")
        return nodes


class SurfsharkProvider(BaseProvider):
    """Surfshark — public cluster API + DNS resolution."""
    name = "surfshark"
    display_name = "Surfshark"
    collection_method = "Public API + DNS"
    threat_relevance = "General VPN coverage"
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
                    "ip_role": "unknown",
                    "prefix": "",
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
                    "ip_role": "ingress",
                    "prefix": "",
                })

        logger.info(f"  {self.display_name}: {len(nodes)} IPs")
        return nodes


class OvpnConfigProvider(BaseProvider):
    """Base class for providers whose servers are discovered by downloading
    an OpenVPN config ZIP, extracting .ovpn files, and parsing 'remote'
    directives into hostnames/IPs.

    Subclasses set config_url and optionally override _parse_country().
    """
    config_url: str = ""

    def _parse_country(self, filename: str) -> str:
        """Extract country code from .ovpn filename. Override for custom patterns."""
        # Try common patterns: "ipvanish-US-...", "CyberGhost_US_...", "us-...", etc.
        name = os.path.splitext(os.path.basename(filename))[0]
        # Look for 2-letter country codes
        parts = re.split(r'[-_.]', name)
        for part in parts:
            if len(part) == 2 and part.isalpha():
                return part.upper()
        return ""

    def fetch(self) -> List[Dict]:
        import io
        import socket
        import zipfile

        logger.info(f"Downloading {self.display_name} config archive...")
        resp = requests.get(self.config_url, timeout=60,
                            headers={"User-Agent": "DomainIntel-VPN/1.0"})
        resp.raise_for_status()

        # Reject excessively large responses (>50MB)
        if len(resp.content) > 50 * 1024 * 1024:
            logger.warning(f"  {self.display_name}: config archive too large ({len(resp.content)} bytes), skipping")
            return []

        nodes = []
        seen_ips = set()
        remote_re = re.compile(r'^remote\s+(\S+)\s+(\d+)', re.MULTILINE)

        # hostname -> first country code seen
        hostname_cc = {}

        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            ovpn_files = [n for n in zf.namelist() if n.endswith('.ovpn')]
            logger.info(f"  {len(ovpn_files)} .ovpn files in archive")

            for name in ovpn_files:
                cc = self._parse_country(name)
                try:
                    content = zf.read(name).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                for m in remote_re.finditer(content):
                    host = m.group(1)
                    if host[0].isdigit():
                        if host not in seen_ips:
                            seen_ips.add(host)
                            nodes.append(self._make_node(host, cc, host))
                    else:
                        hostname_cc.setdefault(host, cc)

        # Parallel DNS resolution using socket (much faster than dig subprocesses)
        def _resolve(host):
            try:
                results = socket.getaddrinfo(host, None, socket.AF_INET)
                return host, list({r[4][0] for r in results})
            except Exception:
                return host, []

        unique_hosts = list(hostname_cc.keys())
        logger.info(f"  Resolving {len(unique_hosts)} unique hostnames...")
        with ThreadPoolExecutor(max_workers=20) as pool:
            for host, ips in pool.map(_resolve, unique_hosts):
                cc = hostname_cc[host]
                for ip in ips:
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        nodes.append(self._make_node(ip, cc, host))

        logger.info(f"  {self.display_name}: {len(nodes)} IPs")
        return nodes

    def _make_node(self, ip: str, cc: str, hostname: str) -> Dict:
        return {
            "ip": ip,
            "provider": self.name,
            "confidence": "confirmed",
            "country": cc,
            "city": "",
            "server_type": "openvpn",
            "asn": "",
            "asn_name": "",
            "source": f"{self.name}_config",
            "source_date": TODAY,
            "hostname": hostname,
            "ip_role": "unknown",
            "prefix": "",
        }


class PIAProvider(BaseProvider):
    """Private Internet Access — public server list API."""
    name = "pia"
    display_name = "Private Internet Access"
    collection_method = "Public API"
    threat_relevance = "Court-proven no-logs (3 FBI subpoenas returned no data)"
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
                        "ip_role": "unknown",
                        "prefix": "",
                    })

        logger.info(f"  {self.display_name}: {len(nodes)} IPs from {len(data.get('regions', []))} regions")
        return nodes


class CyberGhostProvider(DNSEnumProvider):
    """CyberGhost — DNS enumeration of N-CC.cg-dialup.net hostnames."""
    name = "cyberghost"
    display_name = "CyberGhost"
    collection_method = "DNS enumeration"
    threat_relevance = "General VPN coverage"

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
    collection_method = "DNS enumeration"
    threat_relevance = "DPRK confirmed (Mandiant: UNC4899 JumpCloud attack, secondary VPN)"

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
    collection_method = "DNS enumeration"
    threat_relevance = "General VPN coverage; open-source client"

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
    collection_method = "Local client cache"
    threat_relevance = "Verified no-logs (2023 Swedish police raid); privacy-focused"

    def __init__(self, cache_path: str = None):
        self.cache_path = cache_path

    def _find_cache(self) -> str:
        """Find the ProtonVPN Servers.*.bin cache file."""
        if self.cache_path and os.path.exists(self.cache_path):
            return self.cache_path

        # Repo-local seed directory (for CI or manual drops)
        import glob as _glob
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        seed_dir = os.path.join(repo_root, "data", "vpn_seeds", "protonvpn")
        if os.path.isdir(seed_dir):
            current = os.path.join(seed_dir, "Servers.current.bin")
            if os.path.exists(current):
                return current
            matches = _glob.glob(os.path.join(seed_dir, "Servers.*.bin"))
            if matches:
                return matches[0]

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
                "ip_role": "unknown",
                "prefix": "",
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
                "ip_role": "unknown",
                "prefix": "",
            })

        return nodes

    def fetch(self) -> List[Dict]:
        cache = self._find_cache()
        if not cache:
            logger.warning(f"Skipping {self.display_name}: no local client cache found "
                          f"(install ProtonVPN client, drop cache in data/vpn_seeds/protonvpn/, or set cache path)")
            return []

        logger.info(f"Reading {self.display_name} server list from local cache: {cache}")
        nodes = self._parse_cache(cache)
        logger.info(f"  {self.display_name}: {len(nodes)} servers ({sum(1 for n in nodes if n['hostname'])} with hostnames)")
        return nodes


class AstrillProvider(BaseProvider):
    """Astrill VPN — Spur seed list + RDAP validation + Shodan org search."""
    name = "astrill"
    display_name = "Astrill VPN"
    collection_method = "Spur seed + RDAP validation + Shodan org"
    threat_relevance = "PRIMARY DPRK (Mandiant, Microsoft, Spur, Unit 42, SecurityScorecard: UNC5267 + Lazarus)"
    DEFAULT_SEED = "data/vpn_seeds/spur_astrill_2024.txt"

    def __init__(self, seed_path: str = None):
        self.seed_path = seed_path or self.DEFAULT_SEED
        self.rdap = RDAPClient()

    def _seed_date(self) -> str:
        """Parse vintage from seed filename: spur_astrill_2024.txt -> 2024-01-01"""
        basename = os.path.basename(self.seed_path)
        m = re.search(r'(\d{4})', basename)
        if m:
            return f"{m.group(1)}-01-01"
        return TODAY

    def _load_seed(self) -> list:
        if not os.path.exists(self.seed_path):
            logger.warning(f"Astrill seed not found: {self.seed_path}")
            return []
        with open(self.seed_path) as f:
            return [line.strip() for line in f if line.strip()]

    def _rdap_validate(self, ips: list) -> set:
        return self.rdap.validate_astrill_blocks(ips)

    def fetch(self) -> List[Dict]:
        logger.info(f"Fetching {self.display_name} IPs...")
        seed_ips = self._load_seed()
        logger.info(f"  Seed: {len(seed_ips)} IPs from {self.seed_path}")

        seed_dt = self._seed_date()
        if seed_dt != TODAY:
            age_days = (datetime.now() - datetime.strptime(seed_dt, "%Y-%m-%d")).days
            if age_days > 180:
                logger.warning(f"Astrill seed is {age_days} days old ({self.seed_path}); consider refreshing")

        rdap_confirmed = self._rdap_validate(seed_ips)
        logger.info(f"  RDAP confirmed: {len(rdap_confirmed)} IPs")

        shodan_ips = BaseProvider.shodan_org_search("Astrill Systems Corp")

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
                "source_date": seed_dt,
                "hostname": "",
                "ip_role": "egress",
                "prefix": "",
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
                "ip_role": "egress",
                "prefix": "",
            })

        logger.info(f"  {self.display_name}: {len(nodes)} total IPs")
        return nodes


class UrbanVPNProvider(BaseProvider):
    """Urban VPN — free P2P/residential proxy VPN."""
    name = "urbanvpn"
    display_name = "Urban VPN"
    collection_method = "Shodan org search"
    threat_relevance = "DPRK tradecraft (imper.ai: multi-hop stacking with CyberGhost); free P2P VPN with residential IP rotation"

    def fetch(self) -> List[Dict]:
        logger.info(f"Fetching {self.display_name} IPs...")
        shodan_ips = BaseProvider.shodan_org_search("Urban VPN")

        nodes = []
        for ip in shodan_ips:
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
                "ip_role": "unknown",
                "prefix": "",
            })

        logger.info(f"  {self.display_name}: {len(nodes)} total IPs")
        return nodes


# --- New Providers (Tier 1 + Tier 2) ---


class VPNGateProvider(BaseProvider):
    """VPNGate — University of Tsukuba volunteer VPN relay network."""
    name = "vpngate"
    display_name = "VPN Gate"
    collection_method = "Public CSV API"
    threat_relevance = "Censorship circumvention; volunteer-run, dynamic IPs"
    API_URL = "https://www.vpngate.net/api/iphone/"

    def fetch(self) -> List[Dict]:
        logger.info(f"Fetching {self.display_name} server list...")
        resp = requests.get(self.API_URL, timeout=30,
                            headers={"User-Agent": "DomainIntel-VPN/1.0"})
        resp.raise_for_status()

        # Response is CSV with header/footer comment lines starting with *
        lines = [l for l in resp.text.splitlines() if l and not l.startswith("*")]
        nodes = []
        seen_ips = set()

        reader = csv.DictReader(lines)
        for row in reader:
            ip = row.get("IP", "").strip()
            if not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)
            nodes.append({
                "ip": ip,
                "provider": self.name,
                "confidence": "confirmed",
                "country": row.get("CountryShort", "").upper(),
                "city": "",
                "server_type": "openvpn",
                "asn": "",
                "asn_name": "",
                "source": "vpngate_api",
                "source_date": TODAY,
                "hostname": row.get("HostName", ""),
                "ip_role": "unknown",
                "prefix": "",
            })

        logger.info(f"  {self.display_name}: {len(nodes)} active relays")
        return nodes


class IPVanishProvider(OvpnConfigProvider):
    """IPVanish — OpenVPN config ZIP download."""
    name = "ipvanish"
    display_name = "IPVanish"
    collection_method = "Config archive download"
    threat_relevance = "General VPN coverage"
    config_url = "https://configs.ipvanish.com/configs/configs.zip"

    def _parse_country(self, filename: str) -> str:
        # Filenames: ipvanish-US-New-York-nyc-a01.ovpn
        name = os.path.basename(filename)
        m = re.match(r'ipvanish-([A-Z]{2})-', name)
        return m.group(1) if m else ""


class FastVPNProvider(OvpnConfigProvider):
    """FastVPN (Namecheap) — OpenVPN config ZIP download."""
    name = "fastvpn"
    display_name = "FastVPN"
    collection_method = "Config archive download"
    threat_relevance = "General VPN coverage"
    config_url = "https://vpn.ncapi.io/groupedServerList.zip"

    def _parse_country(self, filename: str) -> str:
        # Filenames: NCVPN-AD-Andorra la Vella-TCP.ovpn
        name = os.path.basename(filename)
        m = re.match(r'NCVPN-([A-Z]{2})-', name)
        return m.group(1) if m else ""


class TunnelBearProvider(OvpnConfigProvider):
    """TunnelBear (McAfee) — OpenVPN config ZIP from S3."""
    name = "tunnelbear"
    display_name = "TunnelBear"
    collection_method = "Config archive download"
    threat_relevance = "General VPN coverage"
    config_url = "https://tunnelbear.s3.amazonaws.com/support/linux/openvpn.zip"

    def _parse_country(self, filename: str) -> str:
        # Filenames: CACougar.ovpn, USGrizzly.ovpn, GBMonarch.ovpn
        name = os.path.splitext(os.path.basename(filename))[0]
        # First 2 chars are country code
        if len(name) >= 2 and name[:2].isalpha():
            return name[:2].upper()
        return ""


class AirVPNProvider(BaseProvider):
    """AirVPN — public JSON status API."""
    name = "airvpn"
    display_name = "AirVPN"
    collection_method = "Public API"
    threat_relevance = "General VPN coverage; privacy-focused"
    API_URL = "https://airvpn.org/api/status/"

    def fetch(self) -> List[Dict]:
        logger.info(f"Fetching {self.display_name} server list...")
        resp = requests.get(self.API_URL, timeout=30,
                            headers={"User-Agent": "DomainIntel-VPN/1.0"})
        resp.raise_for_status()
        data = resp.json()

        nodes = []
        seen_ips = set()

        for server in data.get("servers", []):
            # Each server has ip_v4_in1 through ip_v4_in4
            for key in ["ip_v4_in1", "ip_v4_in2", "ip_v4_in3", "ip_v4_in4"]:
                ip = server.get(key, "")
                if not ip or ip in seen_ips:
                    continue
                seen_ips.add(ip)
                nodes.append({
                    "ip": ip,
                    "provider": self.name,
                    "confidence": "confirmed",
                    "country": server.get("country_code", "").upper(),
                    "city": server.get("location", ""),
                    "server_type": "openvpn",
                    "asn": "",
                    "asn_name": "",
                    "source": "airvpn_api",
                    "source_date": TODAY,
                    "hostname": server.get("public_name", ""),
                    "ip_role": "unknown",
                    "prefix": "",
                })

        logger.info(f"  {self.display_name}: {len(nodes)} IPs")
        return nodes


class VyprVPNProvider(DNSEnumProvider):
    """VyprVPN (Certida) — DNS enumeration of {region}{N}.vyprvpn.com."""
    name = "vyprvpn"
    display_name = "VyprVPN"
    collection_method = "DNS enumeration"
    threat_relevance = "General VPN coverage"

    REGIONS = {
        "us": 30, "ca": 10, "uk": 10, "de": 10, "fr": 10, "nl": 10, "se": 10,
        "ch": 10, "no": 5, "dk": 5, "fi": 5, "at": 5, "es": 5, "it": 5,
        "pt": 5, "pl": 5, "cz": 5, "be": 5, "ie": 5, "ro": 5, "bg": 5,
        "hu": 5, "lu": 3, "lv": 3, "lt": 3, "ee": 3, "hr": 3, "sk": 3,
        "si": 3, "gr": 3, "tr": 5, "ru": 5, "ua": 3,
        "jp": 10, "sg": 10, "au": 10, "nz": 5, "hk": 5, "in": 5, "kr": 5,
        "br": 5, "mx": 5, "ar": 3, "za": 3, "il": 3, "th": 3, "vn": 3,
        "my": 3, "ph": 3, "id": 3, "tw": 3, "co": 3,
    }

    def _generate_hostnames(self):
        pairs = []
        for region, max_n in self.REGIONS.items():
            for n in range(1, max_n + 1):
                pairs.append((f"{region}{n}.vyprvpn.com", region))
        return pairs


class ExpressVPNProvider(BaseProvider):
    """ExpressVPN — local app cache + gluetun mirror + Shodan org search.

    Collects IPs from three sources (merged, deduplicated):
    1. Local ExpressVPN app cache (data.json) — highest coverage (~1000 IPs)
    2. Gluetun project's servers.json on GitHub (~390 IPs)
    3. Shodan org search for "ExpressVPN"

    DPRK priority: Mandiant confirmed RGB ORB tunnel usage.
    """
    name = "expressvpn"
    display_name = "ExpressVPN"
    collection_method = "Local cache + Gluetun mirror + Shodan org"
    threat_relevance = "DPRK confirmed (Mandiant: RGB ORB tunnels; Recorded Future: 16.1% NK user share)"
    GLUETUN_URL = "https://raw.githubusercontent.com/qdm12/gluetun/master/internal/storage/servers.json"
    SEED_PATH = os.path.join(
        os.path.dirname(__file__), "..", "data", "vpn_seeds", "expressvpn_servers.json"
    )
    LOCAL_CACHE = os.path.join(
        os.path.dirname(__file__), "..", "data", "vpn_seeds", "expressvpn_data.json"
    )

    # Gluetun uses full country names; map to ISO 2-letter codes
    _COUNTRY_CODES = {
        "albania": "AL", "algeria": "DZ", "andorra": "AD", "argentina": "AR",
        "armenia": "AM", "australia": "AU", "austria": "AT", "bahamas": "BS",
        "bangladesh": "BD", "belgium": "BE", "bhutan": "BT", "bolivia": "BO",
        "bosnia and herzegovina": "BA", "brazil": "BR", "brunei": "BN",
        "bulgaria": "BG", "cambodia": "KH", "canada": "CA", "chile": "CL",
        "colombia": "CO", "costa rica": "CR", "croatia": "HR", "cyprus": "CY",
        "czech republic": "CZ", "denmark": "DK", "ecuador": "EC", "egypt": "EG",
        "estonia": "EE", "finland": "FI", "france": "FR", "georgia": "GE",
        "germany": "DE", "greece": "GR", "guatemala": "GT", "hong kong": "HK",
        "hungary": "HU", "iceland": "IS", "india": "IN", "indonesia": "ID",
        "ireland": "IE", "isle of man": "IM", "israel": "IL", "italy": "IT",
        "japan": "JP", "jersey": "JE", "kazakhstan": "KZ", "kenya": "KE",
        "laos": "LA", "latvia": "LV", "liechtenstein": "LI", "lithuania": "LT",
        "luxembourg": "LU", "macau": "MO", "malaysia": "MY", "malta": "MT",
        "mexico": "MX", "moldova": "MD", "monaco": "MC", "mongolia": "MN",
        "montenegro": "ME", "myanmar": "MM", "nepal": "NP", "netherlands": "NL",
        "new zealand": "NZ", "north macedonia": "MK", "norway": "NO",
        "pakistan": "PK", "panama": "PA", "peru": "PE", "philippines": "PH",
        "poland": "PL", "portugal": "PT", "romania": "RO", "serbia": "RS",
        "singapore": "SG", "slovakia": "SK", "slovenia": "SI", "south africa": "ZA",
        "south korea": "KR", "spain": "ES", "sri lanka": "LK", "sweden": "SE",
        "switzerland": "CH", "taiwan": "TW", "thailand": "TH", "turkey": "TR",
        "ukraine": "UA", "united arab emirates": "AE", "united kingdom": "GB",
        "united states": "US", "uruguay": "UY", "uzbekistan": "UZ",
        "venezuela": "VE", "vietnam": "VN",
    }

    def _normalize_country(self, name: str) -> str:
        """Convert full country name to ISO 2-letter code."""
        if len(name) == 2:
            return name.upper()
        return self._COUNTRY_CODES.get(name.lower(), name[:2].upper() if len(name) >= 2 else "")

    def _load_local_cache(self, seen_ips: set) -> List[Dict]:
        """Load IPs from the local ExpressVPN app cache (data.json)."""
        if not os.path.exists(self.LOCAL_CACHE):
            return []
        try:
            with open(self.LOCAL_CACHE, encoding="utf-8") as f:
                data = json.load(f)
            regions = data.get("cachedModernRegionsList", {}).get("regions", [])
            nodes = []
            for r in regions:
                cc = r.get("country", "")
                name = r.get("name", "")
                for ip in r.get("test_ips", []):
                    if ip and ip not in seen_ips:
                        seen_ips.add(ip)
                        nodes.append({
                            "ip": ip,
                            "provider": self.name,
                            "confidence": "confirmed",
                            "country": cc,
                            "city": "",
                            "server_type": "lightway",
                            "asn": "",
                            "asn_name": "",
                            "source": "expressvpn_local_cache",
                            "source_date": TODAY,
                            "hostname": "",
                            "ip_role": "unknown",
                            "prefix": "",
                        })
            logger.info(f"  Local cache: {len(nodes)} IPs from {len(regions)} regions")
            return nodes
        except Exception as e:
            logger.warning(f"  Failed to parse local cache: {e}")
            return []

    def _load_gluetun_servers(self) -> list:
        """Fetch ExpressVPN servers from gluetun GitHub, fall back to local seed."""
        # Try live fetch first
        try:
            resp = requests.get(self.GLUETUN_URL, timeout=30,
                                headers={"User-Agent": "DomainIntel-VPN/1.0"})
            resp.raise_for_status()
            data = resp.json()
            evpn = data.get("expressvpn", {})
            servers = evpn.get("servers", [])
            if servers:
                logger.info(f"  Gluetun: {len(servers)} ExpressVPN servers from GitHub")
                return servers
        except Exception as e:
            logger.warning(f"  Gluetun fetch failed: {e}")

        # Fall back to local seed
        if os.path.exists(self.SEED_PATH):
            with open(self.SEED_PATH, encoding="utf-8") as f:
                data = json.load(f)
            servers = data if isinstance(data, list) else data.get("servers", [])
            logger.info(f"  Local seed: {len(servers)} servers from {self.SEED_PATH}")
            return servers

        logger.info(f"  No ExpressVPN data available (gluetun fetch failed, no local seed)")
        return []

    def fetch(self) -> List[Dict]:
        logger.info(f"Fetching {self.display_name} IPs...")
        nodes = []
        seen_ips = set()

        # Source 1: Local app cache (highest coverage)
        cache_nodes = self._load_local_cache(seen_ips)
        nodes.extend(cache_nodes)

        # Source 2: Gluetun GitHub (supplements with hostnames + city info)
        for s in self._load_gluetun_servers():
            ips = s.get("ips", [])
            hostname = s.get("hostname", "")
            cc = self._normalize_country(s.get("country", ""))
            for ip in ips:
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    nodes.append({
                        "ip": ip,
                        "provider": self.name,
                        "confidence": "confirmed",
                        "country": cc,
                        "city": s.get("city", ""),
                        "server_type": s.get("vpn", "unknown"),
                        "asn": "",
                        "asn_name": "",
                        "source": "gluetun",
                        "source_date": TODAY,
                        "hostname": hostname,
                        "ip_role": "unknown",
                        "prefix": "",
                    })

        # Supplement with Shodan org search
        shodan_ips = BaseProvider.shodan_org_search("ExpressVPN")
        for ip in shodan_ips - seen_ips:
            seen_ips.add(ip)
            nodes.append({
                "ip": ip,
                "provider": self.name,
                "confidence": "high",
                "country": "",
                "city": "",
                "server_type": "unknown",
                "asn": "",
                "asn_name": "",
                "source": "shodan_org",
                "source_date": TODAY,
                "hostname": "",
                "ip_role": "unknown",
                "prefix": "",
            })

        logger.info(f"  {self.display_name}: {len(nodes)} total IPs")
        return nodes


class HotspotShieldProvider(BaseProvider):
    """Hotspot Shield (Pango/Aura) — DNS resolution + Shodan org search.

    DPRK priority: 63.2% of North Korean VPN users (Recorded Future).
    Uses proprietary Catapult Hydra protocol, no standard configs available.
    """
    name = "hotspotshield"
    display_name = "Hotspot Shield"
    collection_method = "DNS + Shodan org"
    threat_relevance = "DPRK high-usage (Recorded Future: 63.2% NK VPN user share)"

    DNS_HOSTS = ["api.hsselite.com", "api.hotspotshield.com"]

    def fetch(self) -> List[Dict]:
        import socket

        logger.info(f"Fetching {self.display_name} IPs...")
        nodes = []
        seen_ips = set()

        # DNS resolution of known API/server hostnames
        for host in self.DNS_HOSTS:
            try:
                results = socket.getaddrinfo(host, None, socket.AF_INET)
                ips = list({r[4][0] for r in results})
                for ip in ips:
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        nodes.append({
                            "ip": ip,
                            "provider": self.name,
                            "confidence": "confirmed",
                            "country": "",
                            "city": "",
                            "server_type": "hydra",
                            "asn": "",
                            "asn_name": "",
                            "source": f"dns_{host}",
                            "source_date": TODAY,
                            "hostname": host,
                            "ip_role": "unknown",
                            "prefix": "",
                        })
            except Exception:
                pass

        # Shodan org searches for Pango/Aura infra
        for org in ["Pango", "Aura Holdings"]:
            shodan_ips = BaseProvider.shodan_org_search(org)
            for ip in shodan_ips - seen_ips:
                seen_ips.add(ip)
                nodes.append({
                    "ip": ip,
                    "provider": self.name,
                    "confidence": "high",
                    "country": "",
                    "city": "",
                    "server_type": "hydra",
                    "asn": "",
                    "asn_name": "",
                    "source": "shodan_org",
                    "source_date": TODAY,
                    "hostname": "",
                    "ip_role": "unknown",
                    "prefix": "",
                })

        logger.info(f"  {self.display_name}: {len(nodes)} total IPs")
        return nodes


class HMAProvider(OvpnConfigProvider):
    """HideMyAss (Gen Digital/Avast) — OpenVPN config ZIP download.
    NOTE: Config URL redirects to vpn.hidemyass.com which no longer resolves.
    Disabled until a working endpoint is found.
    """
    name = "hma"
    display_name = "HideMyAss"
    collection_method = "Config archive download"
    threat_relevance = "General VPN coverage"
    config_url = "https://www.hidemyass.com/vpn-config/vpn-configs.zip"


class HolaVPNProvider(BaseProvider):
    """Hola VPN — P2P residential proxy network (users are exit nodes for Bright Data).

    Hola's API requires a registered client UUID and session key.
    Auth flow: generate UUID -> POST background_init -> use session_key
    in zgettunnels requests per country.
    """
    name = "holavpn"
    display_name = "Hola VPN"
    collection_method = "Authenticated tunnel API"
    threat_relevance = "P2P residential proxy; users become exit nodes for Bright Data (Luminati) network"

    INIT_URL = "https://client.hola.org/client_cgi/background_init"
    TUNNELS_URL = "https://client.hola.org/client_cgi/zgettunnels"
    EXT_VER = "1.260.637"
    UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

    PROBE_COUNTRIES = [
        "us", "gb", "de", "fr", "nl", "ca", "au", "jp", "sg", "kr",
        "in", "br", "mx", "se", "ch", "no", "it", "es", "ru", "za",
        "il", "tr", "hk", "tw", "th", "vn", "pl", "ro", "ua", "cz",
    ]

    def _register_session(self) -> tuple:
        """Register a client UUID and get session key. Returns (uuid, session_key)."""
        import uuid as _uuid
        client_uuid = str(_uuid.uuid4())
        resp = requests.post(
            self.INIT_URL,
            params={"uuid": client_uuid},
            data={"login": "1", "ver": self.EXT_VER},
            headers={"User-Agent": self.UA},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("blocked"):
            raise RuntimeError(f"Hola blocked UUID {client_uuid}")
        session_key = data.get("key", "")
        if not session_key:
            raise RuntimeError(f"Hola returned no session key: {data}")
        return client_uuid, session_key

    def _get_tunnels(self, client_uuid: str, session_key, country: str) -> list:
        """Get tunnel IPs for a specific country. Returns list of IP strings."""
        import random as _random
        resp = requests.post(
            self.TUNNELS_URL,
            params={
                "country": country,
                "limit": 10,
                "ping_id": str(_random.random()),
                "ext_ver": self.EXT_VER,
                "browser": "chrome",
                "product": "cws",
                "uuid": client_uuid,
                "session_key": session_key,
                "is_premium": "0",
            },
            headers={"User-Agent": self.UA},
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        if data.get("blocked"):
            return []
        # ip_list is a dict of {ip: identifier}
        ip_list = data.get("ip_list", {})
        if isinstance(ip_list, dict):
            return [ip for ip in ip_list.keys() if ip and ip[0].isdigit()]
        return []

    def fetch(self) -> List[Dict]:
        import time as _time

        logger.info(f"Fetching {self.display_name} tunnel IPs...")

        try:
            client_uuid, session_key = self._register_session()
            logger.info(f"  Hola session registered (uuid={client_uuid[:8]}...)")
        except Exception as e:
            logger.warning(f"  Hola session registration failed: {e}")
            return []

        nodes = []
        seen_ips = set()

        for cc in self.PROBE_COUNTRIES:
            try:
                ips = self._get_tunnels(client_uuid, session_key, cc)
                for ip in ips:
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        nodes.append({
                            "ip": ip,
                            "provider": self.name,
                            "confidence": "confirmed",
                            "country": cc.upper(),
                            "city": "",
                            "server_type": "proxy",
                            "asn": "",
                            "asn_name": "",
                            "source": "hola_api",
                            "source_date": TODAY,
                            "hostname": "",
                            "ip_role": "egress",
                            "prefix": "",
                        })
            except Exception as e:
                logger.debug(f"Hola tunnels failed for {cc}: {e}")
            _time.sleep(1.0)  # Rate limit — Hola bans aggressive polling

        logger.info(f"  {self.display_name}: {len(nodes)} tunnel IPs from {len(self.PROBE_COUNTRIES)} countries")
        return nodes


class PrivadoVPNProvider(OvpnConfigProvider):
    """PrivadoVPN — OpenVPN config ZIP download."""
    name = "privadovpn"
    display_name = "PrivadoVPN"
    collection_method = "Config archive download"
    threat_relevance = "General VPN coverage"
    config_url = "https://utils.privadovpn.com/share/udp_tcp.zip"

    # IATA airport code -> ISO country code (common PrivadoVPN locations)
    _IATA_CC = {
        "atl": "US", "bom": "IN", "bud": "HU", "cph": "DK", "dtw": "US",
        "dub": "IE", "fra": "DE", "gru": "BR", "hkg": "HK", "iad": "US",
        "jnb": "ZA", "lax": "US", "lis": "PT", "lhr": "GB", "mad": "ES",
        "mel": "AU", "mex": "MX", "mia": "US", "nrt": "JP", "ord": "US",
        "osa": "JP", "scl": "CL", "sea": "US", "sin": "SG", "sof": "BG",
        "syd": "AU", "tpe": "TW", "vie": "AT", "waw": "PL", "yvr": "CA",
        "yyz": "CA", "zrh": "CH", "ams": "NL", "arn": "SE", "beg": "RS",
        "bkk": "TH", "bog": "CO", "bru": "BE", "bts": "SK", "buh": "RO",
        "hel": "FI", "ist": "TR", "osl": "NO", "prg": "CZ", "rix": "LV",
        "tll": "EE", "vno": "LT", "zag": "HR", "muc": "DE", "mil": "IT",
    }

    def _parse_country(self, filename: str) -> str:
        # Filenames: lis-010.udp.ovpn, yyz-004.tcp.ovpn
        name = os.path.basename(filename)
        m = re.match(r'([a-z]{3})-\d+', name)
        if m:
            return self._IATA_CC.get(m.group(1), "")
        return ""


class FlowVPNProvider(DNSEnumProvider):
    """FlowVPN — DNS enumeration of {cc}.flow.host hostnames."""
    name = "flowvpn"
    display_name = "FlowVPN"
    collection_method = "DNS enumeration"
    threat_relevance = "General VPN coverage"

    # ISO 3166-1 alpha-2 codes for countries where FlowVPN operates
    COUNTRIES = [
        "us", "gb", "de", "fr", "nl", "ca", "au", "jp", "sg", "kr",
        "in", "br", "mx", "se", "ch", "no", "dk", "fi", "at", "it",
        "es", "pt", "pl", "cz", "be", "hu", "bg", "ro", "hr", "ie",
        "lu", "lv", "lt", "ee", "sk", "si", "gr", "tr", "ru", "ua",
        "hk", "tw", "th", "vn", "my", "ph", "id", "nz", "za", "il",
        "ar", "cl", "co", "pe", "pa", "cr", "eg", "ng", "ke", "ma",
        "pk", "bd", "kz", "ge", "md", "mk", "mt", "rs", "ba", "al", "cy",
    ]

    def _generate_hostnames(self):
        pairs = []
        for cc in self.COUNTRIES:
            pairs.append((f"{cc}.flow.host", cc))
        return pairs


class NjallaVPNProvider(DNSEnumProvider):
    """Njalla VPN — DNS enumeration of wg{NNN}.njalla.no WireGuard endpoints."""
    name = "njalla"
    display_name = "Njalla VPN"
    collection_method = "DNS enumeration"
    threat_relevance = "Privacy-focused; operated by same org as Njalla domain registrar"

    def _generate_hostnames(self):
        pairs = []
        # Probe wg001 through wg100; Njalla operates from Sweden/Norway
        for n in range(1, 101):
            pairs.append((f"wg{n:03d}.njalla.no", "no"))
        return pairs


def load_vpn_lookup(csv_path: str = "data/vpn_relay_ips.csv") -> Dict[str, Dict]:
    """Load VPN relay IPs into a lookup dict keyed by IP address.

    Used by enrich_infrastructure.py to add VPN:Provider risk tags.
    Skips prefix-inferred rows (empty ip). Returns empty dict if file doesn't exist.
    """
    if not os.path.exists(csv_path):
        return {}
    lookup = {}
    with open(csv_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("ip"):
                lookup[row["ip"]] = row
    return lookup


# --- Provider Registry ---

PROVIDERS: List[BaseProvider] = [
    # --- Original providers ---
    MullvadProvider(),
    NordVPNProvider(),
    PIAProvider(),
    SurfsharkProvider(),
    ProtonVPNProvider(),
    AstrillProvider(),
    CyberGhostProvider(),
    TorGuardProvider(),
    WindscribeProvider(),
    UrbanVPNProvider(),
    # --- Tier 1: high value / easy collection ---
    ExpressVPNProvider(),
    VPNGateProvider(),
    # IPVanishProvider(),  # Config ZIP returns 403 from CI runners (Cloudflare bot protection)
    FastVPNProvider(),
    VyprVPNProvider(),
    TunnelBearProvider(),
    AirVPNProvider(),
    HotspotShieldProvider(),
    # --- Tier 2: moderate value ---
    # HMAProvider(),  # Config URL redirects to dead host vpn.hidemyass.com
    # HolaVPNProvider(),  # background_init returns 403; likely blocks datacenter/non-residential IPs
    PrivadoVPNProvider(),
    FlowVPNProvider(),
    NjallaVPNProvider(),
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


_DEFAULT_SCORES_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "vpn_provider_scores.csv"
)

SCORE_FIELDS = ["score_prehire", "tier_prehire", "score_posthire", "tier_posthire", "indicator_id"]


def load_scores(csv_path: str = _DEFAULT_SCORES_PATH) -> Dict:
    """Read vpn_provider_scores.csv into a dict keyed by (provider, confidence)."""
    scores = {}
    if not os.path.exists(csv_path):
        logger.warning(f"Scores file not found: {csv_path}")
        return scores
    with open(csv_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (row["provider"], row["confidence"])
            scores[key] = {
                "score_prehire": row["score_prehire"],
                "tier_prehire": row["tier_prehire"],
                "score_posthire": row["score_posthire"],
                "tier_posthire": row["tier_posthire"],
                "indicator_id": row["indicator_id"],
            }
    return scores


def join_scores(nodes: List[Dict], scores_path: str = _DEFAULT_SCORES_PATH) -> None:
    """Merge provider scores onto nodes. Mutates in place."""
    scores = load_scores(scores_path)
    for node in nodes:
        key = (node.get("provider", ""), node.get("confidence", ""))
        match = scores.get(key)
        if match:
            for field in SCORE_FIELDS:
                node[field] = match[field]
        else:
            node["score_prehire"] = "5"
            node["tier_prehire"] = "contextual"
            node["score_posthire"] = "5"
            node["tier_posthire"] = "contextual"
            node["indicator_id"] = ""


def compute_prefix_inferred_rows(nodes: List[Dict], threshold: int = 4) -> List[Dict]:
    """Emit synthetic /24 prefix rows for (provider, ASN) groups with >= threshold IPs."""
    groups = defaultdict(list)
    for n in nodes:
        asn = n.get("asn", "")
        if not asn or asn in SHARED_HOSTING_ASNS:
            continue
        try:
            net24 = ipaddress.ip_network(f"{n['ip']}/24", strict=False)
        except ValueError:
            continue
        groups[(n["provider"], asn, str(net24))].append(n)

    synthetic = []
    for (provider, asn, prefix), members in groups.items():
        if len(members) < threshold:
            continue
        tmpl = members[0]
        row = {
            "ip": "",
            "provider": provider,
            "confidence": "medium",
            "country": tmpl.get("country", ""),
            "city": "",
            "server_type": tmpl.get("server_type", ""),
            "asn": asn,
            "asn_name": tmpl.get("asn_name", ""),
            "source": f"prefix_inferred_from_{len(members)}_ips",
            "source_date": TODAY,
            "hostname": "",
            "collection_method": tmpl.get("collection_method", ""),
            "threat_relevance": tmpl.get("threat_relevance", ""),
            "ip_role": "prefix-inferred",
            "prefix": prefix,
        }
        for sf in SCORE_FIELDS:
            row[sf] = tmpl.get(sf, "")
        synthetic.append(row)

    logger.info(f"Prefix inference: {len(synthetic)} /24 blocks from {len(groups)} groups (threshold={threshold})")
    return synthetic


def compute_rdap_egress_rows(nodes: List[Dict], rdap: "RDAPClient" = None) -> List[Dict]:
    """Infer egress /24 prefixes by querying RDAP for allocated blocks.

    For each (provider, ASN, /24) group with ingress IPs, checks RDAP for the
    allocated block. Any /24 within that block that does NOT already have confirmed
    IPs gets an egress-inferred row.

    Only processes nodes with ip_role='ingress'. Skips SHARED_HOSTING_ASNS.
    """
    import time as _time

    if rdap is None:
        rdap = RDAPClient()

    ingress_nodes = [n for n in nodes if n.get("ip_role") == "ingress"]
    if not ingress_nodes:
        return []

    groups = defaultdict(list)
    for n in ingress_nodes:
        asn = n.get("asn", "")
        if not asn or asn in SHARED_HOSTING_ASNS:
            continue
        try:
            net24 = ipaddress.ip_network(f"{n['ip']}/24", strict=False)
        except ValueError:
            continue
        groups[(n["provider"], asn, str(net24))].append(n)

    covered_24s = set()
    for n in nodes:
        if n.get("ip"):
            try:
                covered_24s.add(str(ipaddress.ip_network(f"{n['ip']}/24", strict=False)))
            except ValueError:
                pass

    # Cache RDAP results by /24 to avoid redundant lookups.
    # Once we know a /24 falls within a larger RDAP block, we cache
    # all /24s in that block to skip future queries.
    net24_to_cidr = {}  # net24_str -> (name, cidr)
    synthetic = []

    for (provider, asn, net24_str), members in groups.items():
        if net24_str not in net24_to_cidr:
            sample_ip = members[0]["ip"]
            name, cidr = rdap.check_block_cidr(sample_ip)
            # Cache this /24 and pre-cache all /24s within the returned block
            net24_to_cidr[net24_str] = (name, cidr)
            if cidr:
                try:
                    block = ipaddress.ip_network(cidr, strict=False)
                    if 16 <= block.prefixlen <= 24:
                        for sub in ([block] if block.prefixlen == 24 else block.subnets(new_prefix=24)):
                            net24_to_cidr.setdefault(str(sub), (name, cidr))
                except ValueError:
                    pass
            _time.sleep(0.3)

        name, cidr = net24_to_cidr[net24_str]
        if not cidr:
            continue

        try:
            allocated = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue

        if allocated.prefixlen < 16 or allocated.prefixlen > 24:
            continue

        tmpl = members[0]
        subnets = [allocated] if allocated.prefixlen == 24 else list(allocated.subnets(new_prefix=24))
        for subnet in subnets:
            subnet_str = str(subnet)
            if subnet_str in covered_24s:
                continue
            covered_24s.add(subnet_str)

            row = {
                "ip": "",
                "provider": provider,
                "confidence": "medium",
                "country": tmpl.get("country", ""),
                "city": "",
                "server_type": tmpl.get("server_type", ""),
                "asn": asn,
                "asn_name": tmpl.get("asn_name", ""),
                "source": "rdap_prefix_expansion",
                "source_date": TODAY,
                "hostname": "",
                "collection_method": tmpl.get("collection_method", ""),
                "threat_relevance": tmpl.get("threat_relevance", ""),
                "ip_role": "egress-inferred",
                "prefix": subnet_str,
            }
            for sf in SCORE_FIELDS:
                row[sf] = tmpl.get(sf, "")
            synthetic.append(row)

    logger.info(f"RDAP egress expansion: {len(synthetic)} inferred /24 blocks from {len(net24_to_cidr)} cached entries")
    return synthetic


def load_existing_csv(path: str) -> Dict[tuple, Dict]:
    """Load existing CSV into a dict keyed by (ip, provider, ip_role)."""
    if not os.path.exists(path):
        return {}
    existing = {}
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (row.get("ip", ""), row.get("provider", ""), row.get("ip_role", "unknown"))
            existing[key] = row
    return existing


def merge_with_existing(
    fresh_rows: List[Dict],
    existing_csv_path: str,
    today: str = TODAY,
) -> List[Dict]:
    """Merge freshly-fetched rows with existing CSV to preserve temporal history.

    - New IPs: first_seen = last_seen = today, active = true
    - Still-present IPs: preserve first_seen, last_seen = today, active = true
    - Disappeared IPs: preserve first_seen and last_seen, active = false
    """
    old = load_existing_csv(existing_csv_path)

    fresh_keys = set()
    merged = []

    for row in fresh_rows:
        key = (row["ip"], row["provider"], row.get("ip_role", "unknown"))
        fresh_keys.add(key)

        prev = old.get(key)
        if prev and prev.get("first_seen"):
            row["first_seen"] = prev["first_seen"]
        else:
            row["first_seen"] = today
        row["last_seen"] = today
        row["active"] = "true"
        merged.append(row)

    # Carry forward historical rows no longer in fresh data
    for key, prev_row in old.items():
        if key not in fresh_keys:
            prev_row["active"] = "false"
            if not prev_row.get("first_seen"):
                prev_row["first_seen"] = prev_row.get("last_seen") or today
            if not prev_row.get("last_seen"):
                prev_row["last_seen"] = today
            merged.append(prev_row)

    return merged


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
            # Inject provider-level metadata
            for n in nodes:
                n["collection_method"] = prov.collection_method
                n["threat_relevance"] = prov.threat_relevance
            all_nodes.extend(nodes)
        except Exception as e:
            logger.error(f"Provider {prov.display_name} failed: {e}")
            continue

    if not all_nodes:
        logger.warning("No VPN IPs collected from any provider.")
        return

    # Normalize all nodes
    for n in all_nodes:
        normalize_node(n)

    # Deduplicate on (ip, provider, ip_role)
    seen = set()
    deduped = []
    for n in all_nodes:
        key = (n["ip"], n["provider"], n.get("ip_role", "unknown"))
        if key not in seen:
            seen.add(key)
            deduped.append(n)
    all_nodes = deduped

    # Enrich ASNs
    enrich_asns(all_nodes, workers=workers)

    # Join provider risk scores (before prefix inference so templates carry scores)
    join_scores(all_nodes)

    # Prefix inference: emit synthetic /24 rows
    prefix_rows = compute_prefix_inferred_rows(all_nodes)

    # RDAP egress expansion: infer adjacent /24s for ingress-only providers
    egress_rows = compute_rdap_egress_rows(all_nodes)

    all_nodes_with_prefix = all_nodes + prefix_rows + egress_rows

    # Merge with existing CSV to preserve temporal history
    all_nodes_with_prefix = merge_with_existing(all_nodes_with_prefix, output)

    # Active-only subset for legacy and per-provider CSVs
    active_rows = [n for n in all_nodes_with_prefix if n.get("active") == "true"]

    # Write primary CSV (all rows including historical)
    write_csv(all_nodes_with_prefix, output)

    # Write legacy compat CSV (active single-IP rows only)
    if "vpn_relay_ips" in output:
        legacy_path = output.replace("vpn_relay_ips", "vpn_exit_ips")
        legacy_rows = [n for n in active_rows if n.get("ip")]
        write_csv(legacy_rows, legacy_path)

    # Write per-provider CSVs (active rows only)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        by_provider = {}
        for n in active_rows:
            by_provider.setdefault(n["provider"], []).append(n)
        for prov_name, nodes in by_provider.items():
            write_csv(nodes, os.path.join(output_dir, f"{prov_name}.csv"))

    logger.info(f"Total: {len(all_nodes)} VPN relay IPs + {len(prefix_rows)} prefix-inferred from {len(by_provider)} providers")


def main():
    parser = argparse.ArgumentParser(description="VPN Exit IP Intelligence Collection")
    parser.add_argument("--output", default="data/vpn_relay_ips.csv", help="Combined output CSV")
    parser.add_argument("--output-dir", default="data/vpn_exit_ips", help="Per-provider output directory")
    parser.add_argument("--workers", type=int, default=20, help="Team Cymru DNS workers")
    parser.add_argument("--providers", nargs="*", default=[], help="Run specific providers only (e.g., mullvad astrill)")
    args = parser.parse_args()

    run(args.output, args.output_dir, args.workers, args.providers)


if __name__ == "__main__":
    main()
