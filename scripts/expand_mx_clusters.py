#!/usr/bin/env python3
"""Expand private MX clusters via OTX passive DNS.

For each private MX host serving 5+ domains, queries OTX to discover
additional domains using that MX. Outputs data/mx_expansion.csv.
"""
import argparse, csv, json, os, sys, logging
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from shared.retry import retry

load_dotenv()
log = logging.getLogger(__name__)

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_HOSTNAME_URL = "https://otx.alienvault.com/api/v1/indicators/hostname/{}/passive_dns"


def extract_mx_targets(infra_index, min_size=5):
    """Return sorted list of private MX hostnames with >= min_size domains."""
    targets = []
    for mx_host, entry in infra_index.get("mx", {}).items():
        if isinstance(entry, dict) and entry.get("private") and len(entry.get("domains", [])) >= min_size:
            targets.append(mx_host)
    return sorted(targets)


@retry(max_attempts=3, backoff_base=2.0)
def query_otx_pdns(hostname):
    """Query OTX passive DNS for a hostname, return list of discovered domains."""
    import requests
    if not OTX_API_KEY:
        log.warning("OTX_API_KEY not set, skipping query for %s", hostname)
        return []
    url = OTX_HOSTNAME_URL.format(hostname)
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code == 200:
        data = resp.json()
        records = data.get("passive_dns", [])
        return list({r.get("hostname") for r in records if r.get("hostname")})
    if resp.status_code == 429:
        log.warning("OTX rate limited for %s", hostname)
    return []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--infra-index", default="docs/data/infra_index.json")
    parser.add_argument("--output", default="data/mx_expansion.csv")
    parser.add_argument("--min-size", type=int, default=5)
    args = parser.parse_args()

    with open(args.infra_index) as f:
        infra_index = json.load(f)

    targets = extract_mx_targets(infra_index, args.min_size)
    log.info("Found %d private MX targets with %d+ domains", len(targets), args.min_size)

    rows = []
    for mx_host in targets:
        known = set(infra_index["mx"][mx_host]["domains"])
        discovered = query_otx_pdns(mx_host)
        new_domains = [d for d in discovered if d not in known]
        for domain in new_domains:
            rows.append({"mx_host": mx_host, "discovered_domain": domain, "source": "otx_pdns"})
        log.info("  %s: %d known, %d discovered, %d new", mx_host, len(known), len(discovered), len(new_domains))

    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["mx_host", "discovered_domain", "source"])
        writer.writeheader()
        writer.writerows(rows)
    log.info("Wrote %d expanded domains to %s", len(rows), args.output)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    main()
