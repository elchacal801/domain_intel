#!/usr/bin/env python3
"""
enrich_infrastructure.py

Enriches a list of domains with infrastructure intelligence:
1. Validates domain
2. Resolves MX records (Mail Exchange)
3. Resolves the Primary MX's IP address (A record)
4. Enriches IP with ASN data via Team Cymru's DNS service

Input: CSV with a 'domain' column (defaults to dea_domains.csv)
Output: CSV with added infrastructure columns (defaults to dea_domains_enriched.csv)

Usage:
  python enrich_infrastructure.py --input dea_domains.csv --output dea_domains_enriched.csv --workers 50
"""

import argparse
import csv
import dns.resolver
import dns.reversename
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from tqdm import tqdm

# Constants
CYMRU_ASN_SUFFIX = "origin.asn.cymru.com"
DEFAULT_TIMEOUT = 5.0
DEFAULT_LIFETIME = 10.0

class InfrastructureResolver:
    def __init__(self, nameservers: Optional[List[str]] = None):
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        else:
            # Use reliable public DNS for reproducibility if local is flaky, 
            # though default local resolver is usually best.
            # Using Google/Cloudflare can sometimes hit rate limits on detailed lookups.
            # We'll stick to system default but set timeouts.
            pass
            
        self.resolver.timeout = DEFAULT_TIMEOUT
        self.resolver.lifetime = DEFAULT_LIFETIME

    def resolve_mx(self, domain: str) -> List[Tuple[int, str]]:
        """Returns sorted list of (priority, hostname) tuples."""
        try:
            answers = self.resolver.resolve(domain, 'MX')
            # Sort by priority
            records = sorted([(r.preference, str(r.exchange).strip('.')) for r in answers], key=lambda x: x[0])
            return records
        except Exception:
            return []

    def resolve_a(self, hostname: str) -> Optional[str]:
        """Returns the first A record IP address."""
        try:
            answers = self.resolver.resolve(hostname, 'A')
            for r in answers:
                return r.to_text()
        except Exception:
            return None
        return None

    def resolve_asn(self, ip_address: str) -> Dict[str, str]:
        """
        Resolves ASN info using Team Cymru IP-to-ASN DNS service.
        Query: reversed_ip.origin.asn.cymru.com TXT
        Response: "ASN | CIDR | CC | REGISTRY | ALLOC_DATE"
        """
        if not ip_address:
            return {}
            
        try:
            rev_name = dns.reversename.from_address(ip_address)
            # from_address gives "4.3.2.1.in-addr.arpa."
            # We need "4.3.2.1.origin.asn.cymru.com"
            # Extract just the reversed numbers
            reversed_ip = str(rev_name).lower().replace('.in-addr.arpa.', '')
            query = f"{reversed_ip}.{CYMRU_ASN_SUFFIX}"
            
            answers = self.resolver.resolve(query, 'TXT')
            for r in answers:
                # Text usually looks like "15169 | 8.8.8.0/24 | US | arin | 2000-03-30"
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

def process_domain(domain: str, resolver_factory) -> Dict:
    # Create a resolver instance per thread if needed, or share thread-safe one.
    # dns.resolver.Resolver is generally thread-safe for queries if not modifying config.
    resolver = resolver_factory
    
    result = {
        "domain": domain,
        "mx_records": "",
        "primary_mx": "",
        "mx_ip": "",
        "asn": "",
        "asn_name": "", # Team Cymru basic query doesn't give name, usually requires another lookup (AS description)
        "bgp_prefix": "",
        "cc": "",
        "error": ""
    }

    try:
        # 1. MX
        mxs = resolver.resolve_mx(domain)
        if mxs:
            result["mx_records"] = ";".join([f"{p} {h}" for p, h in mxs])
            result["primary_mx"] = mxs[0][1] # Lowest preference
            
            # 2. IP of Primary MX
            ip = resolver.resolve_a(result["primary_mx"])
            if ip:
                result["mx_ip"] = ip
                
                # 3. ASN of IP
                asn_data = resolver.resolve_asn(ip)
                result.update(asn_data)
                
                # Optional: Resolve ASN Name? 
                # (Requires "AS<ASN>.asn.cymru.com" TXT query)
                if asn_data.get("asn"):
                    try:
                        as_query = f"AS{asn_data['asn']}.asn.cymru.com"
                        as_answers = resolver.resolver.resolve(as_query, 'TXT')
                        for r in as_answers:
                            # "15169 | US | arin | 2000-03-30 | GOOGLE"
                            parts = [p.strip() for p in r.to_text().strip('"').split('|')]
                            if len(parts) >= 5:
                                result["asn_name"] = parts[4]
                    except Exception:
                        pass
                        
    except Exception as e:
        result["error"] = str(e)

    return result

def main():
    parser = argparse.ArgumentParser(description="Enrich domains with MX/Infrastructure data.")
    parser.add_argument("--input", default="data/dea_domains.csv", help="Input CSV path")
    parser.add_argument("--output", default="data/dea_domains_enriched.csv", help="Output CSV path")
    parser.add_argument("--workers", type=int, default=20, help="Concurrency level")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of domains (for testing)")
    
    args = parser.parse_args()

    # Read domains
    domains = []
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            # Handle headerless logic if 'domain' not in fields, but merge_lists_v3b produces 'domain' header
            if not reader.fieldnames or "domain" not in reader.fieldnames:
                # Fallback if someone edited it manually
                print(f"[!] Warning: 'domain' header not found in {args.input}. using first column.")
                f.seek(0)
                # Re-read plain
                csv_reader = csv.reader(f)
                header = next(csv_reader)
                if "domain" in header:
                     # It was there, maybe casing issue?
                     pass
                else:
                     # Assume file is just list of domains
                     f.seek(0)
                     for line in f:
                         d = line.strip()
                         if d: domains.append(d)
            else:
                for row in reader:
                    if row.get("domain"):
                        domains.append(row["domain"])
    except FileNotFoundError:
        print(f"[!] Input file {args.input} not found.")
        return

    if args.limit > 0:
        domains = domains[:args.limit]

    print(f"[*] Processing {len(domains)} domains with {args.workers} workers...")
    
    # Initialize Resolver
    # sharing one resolver object is fine usually
    resolver = InfrastructureResolver()
    
    results = []
    
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_domain = {executor.submit(process_domain, d, resolver): d for d in domains}
        
        for future in tqdm(as_completed(future_to_domain), total=len(domains), unit="dom"):
            try:
                data = future.result()
                results.append(data)
            except Exception as e:
                # Should be caught inside process_domain, but just in case
                pass

    # Write output
    headers = ["domain", "primary_mx", "mx_ip", "asn", "asn_name", "bgp_prefix", "cc", "registry", "mx_records", "error"]
    
    print(f"[*] Writing results to {args.output}...")
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for r in results:
            # Filter to just our headers
            out_row = {k: r.get(k, "") for k in headers}
            writer.writerow(out_row)
            
    print("[*] Done.")

if __name__ == "__main__":
    main()
