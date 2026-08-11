#!/usr/bin/env python3
"""
enrich_infrastructure.py

High-performance domain enrichment using AsyncIO.
Resolves MX, A, and ASN records for thousands of domains concurrently.

Architecture:
- Async Producer-Consumer pattern (or massive gather with Semaphore)
- dns.asyncresolver for non-blocking DNS
- Team Cymru IP-to-ASN mapping

Completeness contract: every input domain produces exactly one output row.
Domains that cannot be enriched are written with an explanatory ``error``
column instead of being dropped. Transient DNS failures (timeout, SERVFAIL)
are retried with backoff before being recorded; NXDOMAIN is permanent and
recorded without retry. The run reconciles output against input and exits
non-zero on any mismatch.
"""

import argparse
import csv
import asyncio
import dns.asyncresolver
import dns.resolver
import dns.reversename
import dns.exception
import sys
import os
import time
from typing import Dict, List, Set, Tuple
from tqdm.asyncio import tqdm_asyncio
from vpn_ip_intel import load_vpn_lookup

# Constants
CYMRU_ASN_SUFFIX = "origin.asn.cymru.com"
DEFAULT_TIMEOUT = 4.0
DEFAULT_LIFETIME = 8.0
MAX_CONCURRENCY = 200 # Default connections

RETRY_MAX_ATTEMPTS = 3    # attempts per DNS query on transient failures
RETRY_BACKOFF_BASE = 2.0  # delay = base ** (attempt - 1) seconds between attempts

# Transient: worth retrying now and worth re-attempting on the next run
# (timeouts, SERVFAIL/"all nameservers failed"). Permanent: authoritative
# "name does not exist" (NXDOMAIN). NoAnswer means the name exists but has no
# record of the requested type — that is empty data, not an error.
TRANSIENT_DNS_EXCEPTIONS = (dns.exception.Timeout, dns.resolver.NoNameservers)

_DEADLINE = None  # Global deadline timestamp (set by main via --timeout-minutes)

# VPN exit IP lookup for risk tagging
_vpn_lookup = load_vpn_lookup()


class TransientDNSError(Exception):
    """A DNS lookup that still failed with a retryable error after all attempts."""


def _past_deadline() -> bool:
    return _DEADLINE is not None and time.time() > _DEADLINE


def reconcile_or_die(input_domains: Set[str], output_domains: Set[str],
                     label: str = "enrich_infrastructure") -> None:
    """Assert the output domain set equals the input domain set.

    Prints the mismatch (count + sample) and exits non-zero — a shard that
    lost domains must fail its CI job, not report success.
    """
    missing = sorted(input_domains - output_domains)
    extra = sorted(output_domains - input_domains)
    if not missing and not extra:
        print(f"[RECONCILE] OK ({label}): {len(output_domains)} output domains == "
              f"{len(input_domains)} input domains")
        return
    if missing:
        print(f"[RECONCILE] FAIL ({label}): {len(missing)} input domains missing "
              f"from output. Sample: {missing[:10]}")
    if extra:
        print(f"[RECONCILE] FAIL ({label}): {len(extra)} unexpected domains in "
              f"output. Sample: {extra[:10]}")
    sys.exit(1)


class AsyncResolver:
    def __init__(self, nameservers: List[str] = None, max_attempts: int = 1):
        """max_attempts=1 fails fast on transient errors (bulk first pass);
        the retry sweep uses a second instance with max_attempts > 1.
        Inline per-query retries are deliberately NOT the default: on this
        dataset a large fraction of domains have dead nameservers, and
        retrying them inline multiplies dead time per semaphore slot and
        collapses shard throughput."""
        self.resolver = dns.asyncresolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers

        self.resolver.timeout = DEFAULT_TIMEOUT
        self.resolver.lifetime = DEFAULT_LIFETIME
        self.max_attempts = max_attempts

    async def _query(self, qname: str, rdtype: str):
        """One DNS query with bounded retries on transient failures.

        Raises TransientDNSError once attempts are exhausted (or the global
        deadline has passed — no point backing off into a dead run). Permanent
        outcomes (NXDOMAIN, NoAnswer) propagate for the caller to classify.
        """
        attempt = 0
        while True:
            attempt += 1
            try:
                return await self.resolver.resolve(qname, rdtype)
            except TRANSIENT_DNS_EXCEPTIONS as e:
                if attempt >= self.max_attempts or _past_deadline():
                    raise TransientDNSError(f"{rdtype}:{type(e).__name__}") from e
                await asyncio.sleep(RETRY_BACKOFF_BASE ** (attempt - 1))

    async def resolve_mx(self, domain: str) -> List[Tuple[int, str]]:
        """Returns sorted list of (priority, hostname) tuples."""
        try:
            answers = await self._query(domain, 'MX')
        except dns.resolver.NoAnswer:
            return []
        return sorted([(r.preference, str(r.exchange).strip('.')) for r in answers],
                      key=lambda x: x[0])

    async def resolve_ns(self, domain: str) -> List[str]:
        """Returns sorted list of Name Servers."""
        try:
            answers = await self._query(domain, 'NS')
        except dns.resolver.NoAnswer:
            return []
        return sorted([str(r.target).strip('.').lower() for r in answers])

    async def resolve_a(self, hostname: str) -> str:
        """Returns the first A record IP address."""
        if not hostname: return ""
        try:
            answers = await self._query(hostname, 'A')
        except dns.resolver.NoAnswer:
            return ""
        for r in answers:
            return r.to_text()
        return ""

    async def resolve_asn(self, ip_address: str) -> Dict[str, str]:
        """
        Resolves ASN using Team Cymru DNS Interface.
        """
        if not ip_address:
            return {}

        rev_name = dns.reversename.from_address(ip_address)
        reversed_ip = str(rev_name).lower().replace('.in-addr.arpa.', '')
        query = f"{reversed_ip}.{CYMRU_ASN_SUFFIX}"

        try:
            answers = await self._query(query, 'TXT')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return {}  # unrouted/unknown IP — normal, not an error
        for r in answers:
            txt = r.to_text().strip('"')
            parts = [p.strip() for p in txt.split('|')]
            if len(parts) >= 1:
                return {
                    "asn": parts[0],
                    "bgp_prefix": parts[1] if len(parts) > 1 else "",
                    "cc": parts[2] if len(parts) > 2 else "",
                    "registry": parts[3] if len(parts) > 3 else ""
                }
        return {}

    async def resolve_asn_name(self, asn: str) -> str:
        """
        Optional: Start separate query for ASN name if needed.
        Query: AS<ASN>.asn.cymru.com TXT
        """
        if not asn: return ""
        query = f"AS{asn}.asn.cymru.com"
        try:
            answers = await self._query(query, 'TXT')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return ""
        for r in answers:
            txt = r.to_text().strip('"')
            parts = [p.strip() for p in txt.split('|')]
            # "15169 | US | arin | 2000-03-30 | GOOGLE"
            if len(parts) >= 5:
                return parts[4]
        return ""

async def process_domain(sem: asyncio.Semaphore, resolver: AsyncResolver, domain: str) -> Dict:
    async with sem:
        result = {
            "domain": domain,
            "mx_records": "",
            "primary_mx": "",
            "mx_ip": "",
            "asn": "",
            "asn_name": "",
            "bgp_prefix": "",
            "cc": "",
            "registry": "",
            "nameservers": "",
            "a_record": "",
            "a_record_asn": "",
            "a_record_asn_name": "",
            "risk_tags": "",
            "error": ""
        }

        # Past the deadline, emit an accounted row instead of starting lookups.
        # The previous behavior (break out of the collection loop and write only
        # completed rows) silently dropped every unprocessed domain in the shard.
        if _past_deadline():
            result["error"] = "deadline_exceeded"
            return result

        transient: List[str] = []
        nxdomain = False

        try:
            # 1. Resolve NS (New for Nicenic Detection)
            ns_records: List[str] = []
            try:
                ns_records = await resolver.resolve_ns(domain)
            except dns.resolver.NXDOMAIN:
                nxdomain = True
            except TransientDNSError as e:
                transient.append(f"ns:{e}")
            if ns_records:
                result["nameservers"] = ";".join(ns_records)

                # Check for High Risk Registrars (Nicenic)
                # Defined signals: nicendns.com, jpisp.com
                for ns in ns_records:
                    if "nicendns.com" in ns or "jpisp.com" in ns:
                        result["risk_tags"] = "HighRisk:Nicenic"
                        break

            # 2. Resolve A record of domain itself (web hosting IP)
            a_ip = ""
            try:
                a_ip = await resolver.resolve_a(domain)
            except dns.resolver.NXDOMAIN:
                nxdomain = True
            except TransientDNSError as e:
                transient.append(f"a:{e}")
            if a_ip:
                result["a_record"] = a_ip
                try:
                    a_asn_data = await resolver.resolve_asn(a_ip)
                    a_asn = a_asn_data.get("asn", "")
                    if a_asn:
                        result["a_record_asn"] = a_asn
                        result["a_record_asn_name"] = await resolver.resolve_asn_name(a_asn)
                except TransientDNSError as e:
                    transient.append(f"a_asn:{e}")

                # VPN exit node tagging
                if a_ip in _vpn_lookup:
                    vpn_tag = f"VPN:{_vpn_lookup[a_ip]['provider'].title()}"
                    existing = result.get("risk_tags", "")
                    result["risk_tags"] = f"{existing};{vpn_tag}" if existing else vpn_tag

            # 3. Resolve MX
            mxs: List[Tuple[int, str]] = []
            try:
                mxs = await resolver.resolve_mx(domain)
            except dns.resolver.NXDOMAIN:
                nxdomain = True
            except TransientDNSError as e:
                transient.append(f"mx:{e}")
            if mxs:
                result["mx_records"] = ";".join([f"{p} {h}" for p, h in mxs])
                result["primary_mx"] = mxs[0][1]

                # 4. Resolve A Record of Primary MX
                ip = ""
                try:
                    ip = await resolver.resolve_a(result["primary_mx"])
                except dns.resolver.NXDOMAIN:
                    ip = ""  # the MX host not existing is not the domain's NXDOMAIN
                except TransientDNSError as e:
                    transient.append(f"mx_a:{e}")
                result["mx_ip"] = ip

                # 5. Resolve ASN of IP
                if ip:
                    try:
                        asn_data = await resolver.resolve_asn(ip)
                        result.update(asn_data)

                        # 6. Resolve ASN Name (Optional, adds time)
                        # To be super fast, we might skip this or do it only if ASN found
                        if result.get("asn"):
                            result["asn_name"] = await resolver.resolve_asn_name(result["asn"])
                    except TransientDNSError as e:
                        transient.append(f"mx_asn:{e}")

        except Exception as e:
            # Unexpected failure (malformed name, library error): record it,
            # never drop the row.
            result["error"] = str(e) or type(e).__name__
            return result

        has_data = bool(result["nameservers"] or result["a_record"] or result["mx_records"])
        if transient:
            result["error"] = "transient:" + ";".join(transient)
        elif nxdomain and not has_data:
            result["error"] = "NXDOMAIN"

        return result

async def runner(input_file: str, output_file: str, concurrency: int, limit: int = 0,
                 nameservers: List[str] = None):
    # Read domains
    domains = []
    print(f"[*] Reading {input_file}...")
    try:
        with open(input_file, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            # Schema check
            if not reader.fieldnames or "domain" not in reader.fieldnames:
                print("[!] 'domain' header missing. Falling back to plain list read.")
                f.seek(0)
                for line in f:
                    d = line.strip()
                    if d and not d.startswith('#'): domains.append(d)
                # Remove header row if it got caught
                if domains and "domain" in domains[0].lower(): domains.pop(0)
            else:
                for row in reader:
                    if row.get("domain"):
                        domains.append(row["domain"])
    except FileNotFoundError:
        print(f"[!] File not found: {input_file}")
        return

    if limit > 0:
        print(f"[*] Limiting to first {limit} domains.")
        domains = domains[:limit]

    # One task (and one output row) per unique domain, preserving input order.
    seen: Set[str] = set()
    unique_domains: List[str] = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique_domains.append(d)
    if len(unique_domains) != len(domains):
        print(f"[*] Skipping {len(domains) - len(unique_domains)} duplicate input rows.")

    print(f"[*] Enriching {len(unique_domains)} domains with concurrency={concurrency}...")

    # Setup Async
    resolver = AsyncResolver(nameservers=nameservers)
    sem = asyncio.Semaphore(concurrency)

    tasks = [process_domain(sem, resolver, d) for d in unique_domains]

    results = []
    # No deadline break here: once the deadline passes, process_domain
    # short-circuits every remaining task into a fast "deadline_exceeded" row,
    # so the tail drains as error rows instead of being dropped.
    for f in tqdm_asyncio.as_completed(tasks, total=len(tasks), unit="dom"):
        res = await f
        results.append(res)

    by_domain = {r["domain"]: r for r in results}

    # Retry sweep: re-attempt transient failures with backoff, but only in
    # whatever budget remains after the main pass. Keeping retries out of the
    # first pass preserves bulk throughput.
    transient_failed = [d for d in unique_domains
                        if by_domain[d].get("error", "").startswith("transient:")]
    if transient_failed and not _past_deadline():
        print(f"\n[*] Retry sweep: {len(transient_failed)} domains with transient "
              f"failures, up to {RETRY_MAX_ATTEMPTS - 1} more attempts each...")
        retry_resolver = AsyncResolver(nameservers=nameservers,
                                       max_attempts=RETRY_MAX_ATTEMPTS)
        retry_tasks = [process_domain(sem, retry_resolver, d) for d in transient_failed]
        for f in tqdm_asyncio.as_completed(retry_tasks, total=len(retry_tasks), unit="dom"):
            r2 = await f
            # A deadline row means the sweep ran out of time before this domain
            # was re-attempted — keep the original transient row in that case.
            if r2.get("error", "") != "deadline_exceeded":
                by_domain[r2["domain"]] = r2
    # Belt and braces: a domain whose task produced no result still gets a row.
    for d in unique_domains:
        if d not in by_domain:
            by_domain[d] = {"domain": d, "error": "internal:no_result"}

    n_deadline = sum(1 for r in by_domain.values() if r.get("error") == "deadline_exceeded")
    if n_deadline:
        print(f"\n[!] Deadline reached: {n_deadline}/{len(unique_domains)} domains not "
              f"enriched; error rows written instead of dropping them.")

    # Write output — one row per input domain, in input order.
    print(f"[*] Writing results to {output_file}...")
    headers = ["domain", "primary_mx", "mx_ip", "asn", "asn_name", "bgp_prefix", "cc", "registry", "mx_records", "nameservers", "a_record", "a_record_asn", "a_record_asn_name", "risk_tags", "error"]

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for d in unique_domains:
            r = by_domain[d]
            row_out = {h: r.get(h, "") for h in headers}
            writer.writerow(row_out)

    # Reconcile what actually landed on disk against the input. This is the
    # check that would have caught the missing-prefix incident on day one.
    written: Set[str] = set()
    with open(output_file, "r", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            written.add(row["domain"])
    reconcile_or_die(set(unique_domains), written)

    counts = {"succeeded": 0, "permanent_nxdomain": 0, "transient_after_retries": 0,
              "deadline_unprocessed": 0, "other_errors": 0}
    for d in unique_domains:
        err = by_domain[d].get("error", "")
        if not err:
            counts["succeeded"] += 1
        elif err == "NXDOMAIN":
            counts["permanent_nxdomain"] += 1
        elif err.startswith("transient:"):
            counts["transient_after_retries"] += 1
        elif err == "deadline_exceeded":
            counts["deadline_unprocessed"] += 1
        else:
            counts["other_errors"] += 1
    print(f"[SUMMARY] input={len(domains)} output={len(unique_domains)} "
          f"succeeded={counts['succeeded']} "
          f"permanent_nxdomain={counts['permanent_nxdomain']} "
          f"transient_after_retries={counts['transient_after_retries']} "
          f"deadline_unprocessed={counts['deadline_unprocessed']} "
          f"other_errors={counts['other_errors']}")

    print("[*] Done.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/dea_domains.csv")
    parser.add_argument("--output", default="data/dea_domains_enriched.csv")
    parser.add_argument("--workers", type=int, default=MAX_CONCURRENCY, help="Async concurrency limit (default 1000)")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--timeout-minutes", type=int, default=0,
                        help="Global time budget in minutes. 0 = unlimited (default).")
    parser.add_argument("--nameservers", default=None,
                        help="Comma-separated resolver IPs (e.g. 1.1.1.1,8.8.8.8). "
                             "Default: system resolver.")

    args = parser.parse_args()

    global _DEADLINE
    if args.timeout_minutes > 0:
        _DEADLINE = time.time() + args.timeout_minutes * 60
        print(f"[*] Global timeout set to {args.timeout_minutes} minutes.")

    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    nameservers = [n.strip() for n in args.nameservers.split(",") if n.strip()] if args.nameservers else None
    asyncio.run(runner(args.input, args.output, args.workers, args.limit, nameservers))

if __name__ == "__main__":
    main()
