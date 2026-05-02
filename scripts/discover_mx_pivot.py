#!/usr/bin/env python3
"""
discover_mx_pivot.py

Discovers new domains using known-bad MX servers by:
1. Resolving MX records of all domains in the existing actor list
2. Checking if any have changed MX (moved off actor infra = potentially weaponized)
3. Optionally querying OTX passive DNS for MX hostnames to find new domains
4. Outputting newly discovered domains for merge into the pipeline

Target MX servers (pickelhost/ULA-SPF actor):
- mail.pickelhost.com
- mail.eye-mail.net
- park-mx.above.com (third-party, but actor uses it)

Usage:
    python scripts/discover_mx_pivot.py --output data/mx_pivot_findings.csv
"""

import argparse
import asyncio
import csv
import os
import sys
from datetime import datetime
from pathlib import Path

import dns.asyncresolver
import dns.resolver

# Actor MX servers (18 confirmed + 1 third-party)
ACTOR_MX_SERVERS = {
    "mail.pickelhost.com",
    "mail.eye-mail.net",
    "mail.h-email.net",
    "mail.happyisp.com",
    "mail.hope-mail.com",
    "mail.mailerhost.net",
    "mail.mailer-host.com",
    "mail.nickstel.com",
    "mail.yurtmail.com",
    "mail.emailofsteel.com",
    "mail.wallywatts.com",
    "mail.flip-mail.com",
    "mail.post-host.net",
    "mail.mxproc.com",
    "mail.mxhoppr.com",
    "mail.mx-host.net",
    "mail.skrimple.com",
    "mail.b-io.co",
    "park-mx.above.com",
}

# Known actor ULA SPF ranges
ACTOR_ULA_RANGES = [
    "fd68:85f0:7c72",
    "fdcf:abda:4154",
    "fd96:1c8a:43ad",
    "fdec:ae16:fda7",
    "fd92:59f3:510e",
    "fd38:d927:389a",
    "fdd6:e8ab:4e1e",
    "fd1b:212c:a5f9",
]

KNOWN_DOMAINS_FILE = "data/pickelhost_actor_domains.csv"
DEFAULT_CONCURRENCY = 100
DEFAULT_TIMEOUT = 4.0
DEFAULT_LIFETIME = 8.0


async def check_domain_mx(resolver, sem, domain):
    """Check if a domain's MX points to an actor server."""
    async with sem:
        try:
            answers = await resolver.resolve(domain, "MX")
            mx_hosts = [str(r.exchange).strip(".").lower() for r in answers]
            actor_mx = [mx for mx in mx_hosts if any(amx in mx for amx in ACTOR_MX_SERVERS)]
            return {
                "domain": domain,
                "mx_records": ";".join(mx_hosts),
                "has_actor_mx": bool(actor_mx),
                "actor_mx": ";".join(actor_mx),
                "status": "actor_mx" if actor_mx else "changed",
            }
        except dns.resolver.NXDOMAIN:
            return {"domain": domain, "mx_records": "", "has_actor_mx": False, "actor_mx": "", "status": "nxdomain"}
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            return {"domain": domain, "mx_records": "", "has_actor_mx": False, "actor_mx": "", "status": "no_answer"}
        except Exception:
            return {"domain": domain, "mx_records": "", "has_actor_mx": False, "actor_mx": "", "status": "error"}


async def check_new_domain(resolver, sem, domain):
    """Check if a previously unknown domain uses actor MX."""
    async with sem:
        try:
            answers = await resolver.resolve(domain, "MX")
            mx_hosts = [str(r.exchange).strip(".").lower() for r in answers]
            for mx in mx_hosts:
                for actor_mx in ACTOR_MX_SERVERS:
                    if actor_mx in mx:
                        return {"domain": domain, "mx_server": actor_mx, "all_mx": ";".join(mx_hosts)}
        except Exception:
            pass
        return None


async def scan_existing_domains(resolver, known_domains, concurrency):
    """Check which known domains still have actor MX."""
    print(f"[*] Checking {len(known_domains)} known domains for MX changes...")
    sem = asyncio.Semaphore(concurrency)
    tasks = [check_domain_mx(resolver, sem, d) for d in known_domains]

    results = []
    for coro in asyncio.as_completed(tasks):
        result = await coro
        results.append(result)

    still_actor = sum(1 for r in results if r["has_actor_mx"])
    changed = [r for r in results if r["status"] == "changed" and r["mx_records"]]
    nxdomain = sum(1 for r in results if r["status"] == "nxdomain")

    print(f"  [+] Still on actor MX: {still_actor}")
    print(f"  [+] Changed MX (potential weaponization): {len(changed)}")
    print(f"  [+] NXDOMAIN (expired/deleted): {nxdomain}")

    return results, changed


def try_otx_discovery(known_set):
    """Query OTX passive DNS for actor MX hostnames."""
    try:
        sys.path.insert(0, os.path.dirname(__file__))
        from shared.otx_client import query_otx_passive_dns
    except ImportError:
        print("  [-] OTX client not available, skipping OTX discovery")
        return []

    new_domains = []
    for mx_host in ["mail.pickelhost.com", "mail.eye-mail.net"]:
        print(f"  [*] Querying OTX for {mx_host}...")
        try:
            otx_domains = query_otx_passive_dns(mx_host)
            for d in otx_domains:
                if d not in known_set and d not in ACTOR_MX_SERVERS:
                    new_domains.append({"domain": d, "mx_server": mx_host, "source": "otx"})
        except Exception as e:
            print(f"  [-] OTX error for {mx_host}: {e}")

    print(f"  [+] OTX discovered {len(new_domains)} new domains")
    return new_domains


def main():
    parser = argparse.ArgumentParser(description="Discover domains on known-bad MX servers")
    parser.add_argument("-o", "--output", default="data/mx_pivot_findings.csv")
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--skip-otx", action="store_true", help="Skip OTX passive DNS queries")
    parser.add_argument("--check-changes", action="store_true", help="Report domains that changed MX")
    args = parser.parse_args()

    # Load known domains
    known_domains = set()
    if os.path.exists(KNOWN_DOMAINS_FILE):
        with open(KNOWN_DOMAINS_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                d = row.get("discovered_domain", "").strip()
                if d:
                    known_domains.add(d)
    print(f"[*] Loaded {len(known_domains)} known actor domains")

    # Setup resolver
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.timeout = DEFAULT_TIMEOUT
    resolver.lifetime = DEFAULT_LIFETIME

    new_discoveries = []

    # 1. OTX passive DNS discovery
    if not args.skip_otx:
        otx_results = try_otx_discovery(known_domains)
        new_discoveries.extend(otx_results)

    # 2. Check existing domains for MX changes (optional)
    if args.check_changes and known_domains:
        sample = list(known_domains)[:5000]  # Sample to avoid excessive DNS
        _, changed = asyncio.run(scan_existing_domains(resolver, sample, args.concurrency))
        if changed:
            print(f"\n[!] Domains that CHANGED MX (weaponized?):")
            for c in changed[:20]:
                print(f"    {c['domain']} -> {c['mx_records']}")

    # Write output
    output_path = Path(args.output)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["discovered_domain", "mx_server", "source", "discovery_date"])
        writer.writeheader()
        for d in new_discoveries:
            writer.writerow({
                "discovered_domain": d.get("domain", ""),
                "mx_server": d.get("mx_server", ""),
                "source": d.get("source", "mx_pivot"),
                "discovery_date": datetime.now().strftime("%Y-%m-%d"),
            })

    print(f"\n[+] Wrote {len(new_discoveries)} new domains to {output_path}")

    # Exit code 1 if new findings (for GitHub Actions alerting)
    if new_discoveries:
        sys.exit(1)


if __name__ == "__main__":
    main()
