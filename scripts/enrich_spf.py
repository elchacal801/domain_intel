#!/usr/bin/env python3
"""
enrich_spf.py

SPF/TXT record enrichment for the domain_intel pipeline.
Resolves TXT records for all domains and extracts SPF data,
with specific detection of ULA IPv6 patterns used by known
threat actors (pickelhost/eye-mail/above.com cluster).

Adds columns:
  - spf_record: Full SPF TXT record
  - spf_ula_match: True if SPF contains ULA (fd00::/8) IPv6 range
  - spf_ula_range: The specific ULA /48 range(s) found
  - spf_known_actor: Description if range matches known actor infrastructure

Architecture: Mirrors enrich_infrastructure.py — async DNS with semaphore.
"""

import argparse
import asyncio
import csv
import re
import sys
from typing import Dict, List

import dns.asyncresolver
import dns.resolver

# Known actor ULA ranges (pickelhost/eye-mail/above.com cluster)
KNOWN_ACTOR_RANGES = {
    "fd68:85f0:7c72": "pickelhost-alpha (primary relay)",
    "fdcf:abda:4154": "above-bravo (secondary relay / brand typosquats)",
    "fd96:1c8a:43ad": "pickelhost-charlie (admin / eye-mail self)",
    "fd92:59f3:510e": "delta (tertiary relay)",
    "fd38:d927:389a": "echo (walmart/.ws cluster)",
    "fdd6:e8ab:4e1e": "foxtrot (registrar impersonation)",
    "fdec:ae16:fda7": "golf (eye-mail primary relay)",
    "fd1b:212c:a5f9": "hotel (southafricaproject)",
}

DEFAULT_TIMEOUT = 4.0
DEFAULT_LIFETIME = 8.0
MAX_CONCURRENCY = 200


async def resolve_spf(resolver, sem, domain: str) -> Dict:
    """Resolve TXT records and extract SPF data."""
    async with sem:
        result = {
            "domain": domain,
            "spf_record": "",
            "spf_ula_match": False,
            "spf_ula_range": "",
            "spf_known_actor": "",
        }

        try:
            answers = await resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = "".join(
                    s.decode("utf-8", errors="replace") for s in rdata.strings
                )
                if txt.lower().startswith("v=spf1"):
                    result["spf_record"] = txt

                    # Extract ULA IPv6 ranges
                    ula_ranges = []
                    actor_matches = []
                    for part in txt.split():
                        if part.lower().startswith("ip6:fd"):
                            ula_range = part[4:]  # strip "ip6:"
                            ula_ranges.append(ula_range)
                            # Check known actor ranges
                            prefix = ula_range.split("/")[0][:14]
                            for known_prefix, desc in KNOWN_ACTOR_RANGES.items():
                                if known_prefix in ula_range:
                                    actor_matches.append(desc)

                    if ula_ranges:
                        result["spf_ula_match"] = True
                        result["spf_ula_range"] = ";".join(ula_ranges)
                        result["spf_known_actor"] = ";".join(actor_matches)
                    break  # Only need first SPF record

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
        ):
            pass
        except Exception:
            pass

        return result


async def runner(input_file: str, output_file: str, concurrency: int, limit: int = 0):
    """Main async runner. Supports two modes:
    1. Standalone: input is domain list, output is SPF-only CSV
    2. Pipeline: input is probed CSV with 'domain' column, output merges SPF columns back
    """
    # Read domains and detect mode
    domains = []
    is_pipeline = False
    original_rows = []
    original_headers = []

    print(f"[*] Reading {input_file}...")
    try:
        with open(input_file, "r", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames and "domain" in reader.fieldnames:
                original_headers = list(reader.fieldnames)
                # Check if this is a full pipeline CSV (has enrichment columns)
                if "primary_mx" in original_headers or "a_record" in original_headers:
                    is_pipeline = True
                for row in reader:
                    if row.get("domain"):
                        domains.append(row["domain"])
                        if is_pipeline:
                            original_rows.append(row)
            else:
                f.seek(0)
                for line in f:
                    d = line.strip()
                    if d and not d.startswith("#"):
                        domains.append(d)
                if domains and "domain" in domains[0].lower():
                    domains.pop(0)
    except FileNotFoundError:
        print(f"[!] File not found: {input_file}")
        return

    if limit > 0:
        domains = domains[:limit]
        if is_pipeline:
            original_rows = original_rows[:limit]

    print(f"[*] Resolving SPF for {len(domains)} domains (concurrency={concurrency}, mode={'pipeline' if is_pipeline else 'standalone'})...")

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.timeout = DEFAULT_TIMEOUT
    resolver.lifetime = DEFAULT_LIFETIME

    sem = asyncio.Semaphore(concurrency)
    tasks = [resolve_spf(resolver, sem, d) for d in domains]

    results = []
    completed = 0
    for coro in asyncio.as_completed(tasks):
        res = await coro
        results.append(res)
        completed += 1
        if completed % 5000 == 0 or completed == len(domains):
            print(f"  [{completed}/{len(domains)}]")

    # Stats
    with_spf = sum(1 for r in results if r["spf_record"])
    with_ula = sum(1 for r in results if r["spf_ula_match"])
    with_actor = sum(1 for r in results if r["spf_known_actor"])
    print(f"[*] Results: {len(results)} total, {with_spf} with SPF, {with_ula} with ULA, {with_actor} known actor")

    # Build lookup
    spf_lookup = {r["domain"]: r for r in results}

    spf_columns = ["spf_record", "spf_ula_match", "spf_ula_range", "spf_known_actor"]

    if is_pipeline:
        # Merge SPF columns into original CSV
        out_headers = original_headers + [c for c in spf_columns if c not in original_headers]
        print(f"[*] Merging SPF columns into pipeline CSV -> {output_file}...")
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=out_headers)
            writer.writeheader()
            for row in original_rows:
                domain = row.get("domain", "")
                spf_data = spf_lookup.get(domain, {})
                for col in spf_columns:
                    row[col] = spf_data.get(col, "")
                writer.writerow(row)
    else:
        # Standalone mode: write SPF-only CSV
        headers = ["domain"] + spf_columns
        print(f"[*] Writing to {output_file}...")
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for r in sorted(results, key=lambda x: x["domain"]):
                writer.writerow(r)

    print(f"[+] Done. {output_file}")


def main():
    parser = argparse.ArgumentParser(description="SPF/TXT enrichment for domain_intel pipeline")
    parser.add_argument("-i", "--input", required=True, help="Input CSV (must have 'domain' column) or text file")
    parser.add_argument("-o", "--output", required=True, help="Output CSV with SPF columns")
    parser.add_argument("-c", "--concurrency", type=int, default=MAX_CONCURRENCY)
    parser.add_argument("-l", "--limit", type=int, default=0, help="Limit domains to process")
    args = parser.parse_args()

    asyncio.run(runner(args.input, args.output, args.concurrency, args.limit))


if __name__ == "__main__":
    main()
