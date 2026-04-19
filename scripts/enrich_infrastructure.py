#!/usr/bin/env python3
"""
enrich_infrastructure.py

High-performance domain enrichment using AsyncIO.
Resolves MX, A, and ASN records for thousands of domains concurrently.

Architecture:
- Async Producer-Consumer pattern (or massive gather with Semaphore)
- dns.asyncresolver for non-blocking DNS
- Team Cymru IP-to-ASN mapping
"""

import argparse
import csv
import asyncio
import dns.asyncresolver
import dns.resolver
import dns.reversename
import sys
import os
from typing import Dict, List, Tuple
from tqdm.asyncio import tqdm_asyncio
from vpn_ip_intel import load_vpn_lookup

# Constants
CYMRU_ASN_SUFFIX = "origin.asn.cymru.com"
DEFAULT_TIMEOUT = 4.0
DEFAULT_LIFETIME = 8.0
MAX_CONCURRENCY = 200 # Default connections

# VPN exit IP lookup for risk tagging
_vpn_lookup = load_vpn_lookup()

class AsyncResolver:
    def __init__(self, nameservers: List[str] = None):
        self.resolver = dns.asyncresolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        
        self.resolver.timeout = DEFAULT_TIMEOUT
        self.resolver.lifetime = DEFAULT_LIFETIME

    async def resolve_mx(self, domain: str) -> List[Tuple[int, str]]:
        """Returns sorted list of (priority, hostname) tuples."""
        try:
            answers = await self.resolver.resolve(domain, 'MX')
            records = sorted([(r.preference, str(r.exchange).strip('.')) for r in answers], key=lambda x: x[0])
            return records
        except Exception:
            return []

    async def resolve_ns(self, domain: str) -> List[str]:
        """Returns sorted list of Name Servers."""
        try:
            answers = await self.resolver.resolve(domain, 'NS')
            return sorted([str(r.target).strip('.').lower() for r in answers])
        except Exception:
            return []

    async def resolve_a(self, hostname: str) -> str:
        """Returns the first A record IP address."""
        if not hostname: return ""
        try:
            answers = await self.resolver.resolve(hostname, 'A')
            for r in answers:
                return r.to_text()
        except Exception:
            return ""
        return ""

    async def resolve_asn(self, ip_address: str) -> Dict[str, str]:
        """
        Resolves ASN using Team Cymru DNS Interface.
        """
        if not ip_address:
            return {}
            
        try:
            rev_name = dns.reversename.from_address(ip_address)
            reversed_ip = str(rev_name).lower().replace('.in-addr.arpa.', '')
            query = f"{reversed_ip}.{CYMRU_ASN_SUFFIX}"
            
            answers = await self.resolver.resolve(query, 'TXT')
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
        except Exception:
            pass
        return {}

    async def resolve_asn_name(self, asn: str) -> str:
        """
        Optional: Start separate query for ASN name if needed.
        Query: AS<ASN>.asn.cymru.com TXT
        """
        if not asn: return ""
        try:
            query = f"AS{asn}.asn.cymru.com"
            answers = await self.resolver.resolve(query, 'TXT')
            for r in answers:
                txt = r.to_text().strip('"')
                parts = [p.strip() for p in txt.split('|')]
                # "15169 | US | arin | 2000-03-30 | GOOGLE"
                if len(parts) >= 5:
                    return parts[4]
        except Exception:
            pass
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
        
        try:
            # 1. Resolve NS (New for Nicenic Detection)
            ns_records = await resolver.resolve_ns(domain)
            if ns_records:
                result["nameservers"] = ";".join(ns_records)
                
                # Check for High Risk Registrars (Nicenic)
                # Defined signals: nicendns.com, jpisp.com
                for ns in ns_records:
                    if "nicendns.com" in ns or "jpisp.com" in ns:
                        result["risk_tags"] = "HighRisk:Nicenic"
                        break

            # 2. Resolve A record of domain itself (web hosting IP)
            a_ip = await resolver.resolve_a(domain)
            if a_ip:
                result["a_record"] = a_ip
                a_asn_data = await resolver.resolve_asn(a_ip)
                a_asn = a_asn_data.get("asn", "")
                if a_asn:
                    result["a_record_asn"] = a_asn
                    result["a_record_asn_name"] = await resolver.resolve_asn_name(a_asn)

                # VPN exit node tagging
                if a_ip in _vpn_lookup:
                    vpn_tag = f"VPN:{_vpn_lookup[a_ip]['provider'].title()}"
                    existing = result.get("risk_tags", "")
                    result["risk_tags"] = f"{existing};{vpn_tag}" if existing else vpn_tag

            # 3. Resolve MX
            mxs = await resolver.resolve_mx(domain)
            if mxs:
                result["mx_records"] = ";".join([f"{p} {h}" for p, h in mxs])
                result["primary_mx"] = mxs[0][1]
                
                # 4. Resolve A Record of Primary MX
                ip = await resolver.resolve_a(result["primary_mx"])
                result["mx_ip"] = ip

                # 5. Resolve ASN of IP
                if ip:
                    asn_data = await resolver.resolve_asn(ip)
                    result.update(asn_data)

                    # 6. Resolve ASN Name (Optional, adds time)
                    # To be super fast, we might skip this or do it only if ASN found
                    if result.get("asn"):
                        result["asn_name"] = await resolver.resolve_asn_name(result["asn"])

        except Exception as e:
            result["error"] = str(e)
            
        return result

async def runner(input_file: str, output_file: str, concurrency: int, limit: int = 0):
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

    print(f"[*] Enriched {len(domains)} domains with concurrency={concurrency}...")
    
    # Setup Async
    resolver = AsyncResolver()
    sem = asyncio.Semaphore(concurrency)
    
    tasks = [process_domain(sem, resolver, d) for d in domains]
    
    results = []
    # Use tqdm to show progress of completed futures
    for f in tqdm_asyncio.as_completed(tasks, total=len(tasks), unit="dom"):
        res = await f
        results.append(res)
        
    # Write output
    print(f"[*] Writing results to {output_file}...")
    headers = ["domain", "primary_mx", "mx_ip", "asn", "asn_name", "bgp_prefix", "cc", "registry", "mx_records", "nameservers", "a_record", "a_record_asn", "a_record_asn_name", "risk_tags", "error"]
    
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for r in results:
            # Clean dict
            row_out = {h: r.get(h, "") for h in headers}
            writer.writerow(row_out)
            
    print("[*] Done.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/dea_domains.csv")
    parser.add_argument("--output", default="data/dea_domains_enriched.csv")
    parser.add_argument("--workers", type=int, default=MAX_CONCURRENCY, help="Async concurrency limit (default 1000)")
    parser.add_argument("--limit", type=int, default=0)
    
    args = parser.parse_args()
    
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    asyncio.run(runner(args.input, args.output, args.workers, args.limit))

if __name__ == "__main__":
    main()
