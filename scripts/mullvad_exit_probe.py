#!/usr/bin/env python3
"""
mullvad_exit_probe.py

Discovers Mullvad VPN exit IPs by probing each relay via its SOCKS5 proxy.
Requires an active Mullvad WireGuard connection.

Usage:
  python mullvad_exit_probe.py [--output data/vpn_seeds/mullvad_exit_ips.csv] [--limit N]
"""

import argparse
import csv
import logging
import os
import sys
import time
from datetime import date
from typing import Dict, List, Optional

import requests

sys.path.insert(0, os.path.dirname(__file__))
from shared.retry import retry

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

TODAY = date.today().isoformat()
API_URL = "https://api.mullvad.net/www/relays/all/"
ECHO_URL = "https://am.i.mullvad.net/json"
DEFAULT_OUTPUT = os.path.join(os.path.dirname(__file__), "..", "data", "vpn_seeds", "mullvad_exit_ips.csv")
SEED_FIELDS = ["relay_hostname", "ingress_ip", "exit_ip", "probe_date"]


def fetch_relays() -> List[Dict]:
    """Fetch active Mullvad relays with SOCKS5 info."""
    resp = requests.get(API_URL, timeout=30)
    resp.raise_for_status()
    relays = []
    for s in resp.json():
        if not s.get("active") or not s.get("ipv4_addr_in"):
            continue
        if not s.get("socks_name"):
            continue
        relays.append({
            "hostname": s["hostname"],
            "ipv4_addr_in": s["ipv4_addr_in"],
            "socks_name": s["socks_name"],
            "socks_port": s.get("socks_port", 1080),
            "country_code": s.get("country_code", ""),
            "city_name": s.get("city_name", ""),
        })
    logger.info(f"Fetched {len(relays)} active relays with SOCKS5")
    return relays


@retry(max_attempts=2, backoff_base=2.0, exceptions=(requests.RequestException,))
def probe_relay(relay: Dict) -> Optional[str]:
    """Probe a single relay's SOCKS5 proxy to discover its exit IP.
    Returns the exit IP string, or None on failure.
    """
    proxy_url = f"socks5h://{relay['socks_name']}:{relay['socks_port']}"
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        resp = requests.get(ECHO_URL, proxies=proxies, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        exit_ip = data.get("ip", "")
        if exit_ip:
            return exit_ip
    except Exception as e:
        logger.debug(f"Probe failed for {relay['hostname']}: {e}")
        return None
    return None


def write_results(results: List[Dict], path: str) -> None:
    """Write probe results to CSV."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SEED_FIELDS)
        writer.writeheader()
        writer.writerows(results)
    logger.info(f"Wrote {len(results)} exit IPs to {path}")


def main():
    parser = argparse.ArgumentParser(description="Mullvad Exit IP Probe via SOCKS5")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output CSV path")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of relays to probe (0 = all)")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between probes in seconds")
    args = parser.parse_args()

    relays = fetch_relays()
    if args.limit:
        relays = relays[:args.limit]

    logger.info(f"Probing {len(relays)} relays (delay={args.delay}s)...")
    results = []
    for i, relay in enumerate(relays, 1):
        logger.info(f"[{i}/{len(relays)}] {relay['hostname']} ({relay['ipv4_addr_in']})...")
        exit_ip = probe_relay(relay)
        if exit_ip:
            results.append({
                "relay_hostname": relay["hostname"],
                "ingress_ip": relay["ipv4_addr_in"],
                "exit_ip": exit_ip,
                "probe_date": TODAY,
            })
            logger.info(f"  -> exit: {exit_ip}")
        else:
            logger.warning(f"  -> FAILED")

        if i < len(relays):
            time.sleep(args.delay)

    write_results(results, args.output)
    logger.info(f"Done. {len(results)}/{len(relays)} relays probed successfully.")


if __name__ == "__main__":
    main()
