#!/usr/bin/env python3
"""
enrich_shodan.py

Enriches domain data with Shodan intelligence.
1. Resolves Domain -> IP (if missing).
2. Queries Shodan IP info (Ports, Vulns, Tags) with Caching & Budgeting.
3. Adds intelligence to CSV.
"""

import argparse
import csv
import os
import sys
import logging
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from dotenv import load_dotenv
import shodan

from shodan_utils import CreditBudget, ShodanCache

# Setup Logging
logging.basicConfig(level=logging.INFO, format='[*] %(message)s')
log = logging.getLogger("enrich_shodan")
log.setLevel(logging.INFO)

def resolve_domain(domain: str, timeout: float = 3.0) -> str:
    """Resolves A record for a domain with a hard timeout."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.timeout, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(old_timeout)

def process_shodan(api_key: str, domains: List[Dict], output_file: str, budget: int):
    # Init Utils
    budget_tracker = CreditBudget()
    budget_tracker.set_budget(budget)
    cache = ShodanCache()
    
    try:
        api = shodan.Shodan(api_key)
    except Exception as e:
        log.error(f"Failed to init Shodan API: {e}")
        return

    # 1. Gather IPs (concurrent DNS resolution with timeout)
    log.info(f"Resolving IPs for {len(domains)} domains...")
    ip_map = {} # ip -> [domains]
    unique_ips = set()

    # Separate rows that already have IPs from those needing resolution
    needs_resolve = []
    for row in domains:
        domain = row.get("domain")
        if not domain: continue
        ip = row.get("mx_ip") or row.get("a_record")
        if ip and ip.strip():
            unique_ips.add(ip)
            ip_map.setdefault(ip, []).append(row)
        else:
            needs_resolve.append(row)

    log.info(f"  {len(domains) - len(needs_resolve)} already have IPs, resolving {len(needs_resolve)} via DNS...")

    # Concurrent DNS resolution with 20 threads and 3s timeout per domain
    def _resolve_row(row):
        return row, resolve_domain(row["domain"], timeout=3.0)

    resolved_count = 0
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_resolve_row, row): row for row in needs_resolve}
        for future in as_completed(futures):
            row, ip = future.result()
            resolved_count += 1
            if resolved_count % 1000 == 0:
                log.info(f"  DNS progress: {resolved_count}/{len(needs_resolve)}")
            if ip:
                unique_ips.add(ip)
                ip_map.setdefault(ip, []).append(row)

    log.info(f"Found {len(unique_ips)} unique IPs to scan.")

    # 2. Query Shodan (Concurrent with Rate Limiting)
    log.info(f"Scanning {len(unique_ips)} IPs via Shodan...")
    
    shodan_results = {}
    
    # Simple Rate Limiter to respect API limits (e.g., 5-10 RPS)
    class RateLimiter:
        def __init__(self, max_rps):
            self.delay = 1.0 / max_rps
            self.lock = threading.Lock()
            self.last_call = 0

        def wait(self):
            with self.lock:
                now = time.time()
                elapsed = now - self.last_call
                to_wait = self.delay - elapsed
                if to_wait > 0:
                    time.sleep(to_wait)
                self.last_call = time.time()

    # Target ~5 RPS to be safe but faster than sequential
    rate_limiter = RateLimiter(max_rps=5)
    
    def _scan_ip(ip):
        cache_key = f"host:{ip}"
        
        # Check Cache
        cached_data = cache.get(cache_key)
        if cached_data:
            return ip, cached_data
            
        rate_limiter.wait()
            
        # Check Budget
        if not budget_tracker.check_can_spend(1):
            return ip, None
            
        # Query API
        try:
            budget_tracker.spend(1)
            host_info = api.host(ip, minify=True)
            
            s_data = {
                "ip": ip,
                "ports": ";".join([str(p) for p in host_info.get("ports", [])]),
                "tags": ";".join(host_info.get("tags", [])),
                "os": host_info.get("os", "") or "",
                "hostnames": ";".join(host_info.get("hostnames", [])),
                "vulns": ";".join(host_info.get("vulns", []))
            }
            
            cache.set(cache_key, s_data)
            return ip, s_data
            
        except shodan.APIError as e:
            if "No information available" in str(e):
                empty_data = {"ip": ip, "ports": "", "vulns": "", "tags": "", "os": "", "hostnames": ""}
                cache.set(cache_key, empty_data)
                return ip, empty_data
            else:
                log.error(f"  [!] API Error for {ip}: {e}")
                return ip, None
        except Exception as e:
            log.error(f"  [!] Error scanning {ip}: {e}")
            return ip, None

    # Run Parallel Scans
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_scan_ip, ip): ip for ip in unique_ips}
        
        completed = 0
        total = len(unique_ips)
        
        for future in as_completed(futures):
            ip, result = future.result()
            completed += 1
            if completed % 10 == 0:
                print(f"[*] Shodan Scan Progress: {completed}/{total}", end='\r')
            
            if result:
                shodan_results[ip] = result

    print(f"\n[*] Shodan scan complete. Processed {len(shodan_results)} IPs.")

    # 3. Map back to results
    results = []
    
    # Using ip_map to distribute results
    for ip, rows in ip_map.items():
        s_data = shodan_results.get(ip)
        
        for r in rows:
            enriched = r.copy()
            if s_data:
                enriched["shodan_ip"] = ip
                enriched.update(s_data)
            else:
                # If we ran out of budget or failed, we leave fields empty
                enriched["shodan_ip"] = ip
                enriched["ports"] = ""
                enriched["vulns"] = ""
                enriched["tags"] = ""
                enriched["os"] = ""
                enriched["hostnames"] = ""
            results.append(enriched)
    
    # 4. Write Output
    if not results:
        log.info("No results found.")
        cache.close()
        return

    # Collect all unique keys
    all_keys = set()
    for r in results:
        all_keys.update(r.keys())
    headers = sorted(list(all_keys))
    
    # Prioritize columns
    priority = ['domain', 'ip', 'shodan_ip', 'ports', 'vulns', 'tags']
    for p in reversed(priority):
        if p in headers:
            headers.insert(0, headers.pop(headers.index(p)))

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(results)
        
    log.info(f"Wrote {len(results)} rows to {output_file}")
    cache.close()


def main():
    load_dotenv()
    API_KEY = os.getenv("SHODAN_API_KEY")
    if not API_KEY:
        log.error("Error: SHODAN_API_KEY not found in .env")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/dea_domains_probed.csv")
    parser.add_argument("--output", default="data/shodan_intelligence.csv")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--budget", type=int, default=20, help="Max credits to spend")
    args = parser.parse_args()

    # Read Input
    domains = []
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                domains.append(row)
    except FileNotFoundError:
        log.error("Input file not found.")
        sys.exit(1)

    if args.limit > 0:
        domains = domains[:args.limit]

    process_shodan(API_KEY, domains, args.output, args.budget)

if __name__ == "__main__":
    main()
