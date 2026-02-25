#!/usr/bin/env python3
"""
openclaw_scan.py

Scans for exposed OpenClaw/Moltbot/Clawdbot instances.
Uses Shodan queries (Tier 1, 2, 3) to find instances on port 18789.
Classifies risk based on auth status, version, and corporate exposure.
"""

import argparse
import csv
import os
import sys
import logging
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Set, Any
from pathlib import Path
from dotenv import load_dotenv
import shodan

from shodan_utils import CreditBudget, ShodanCache, IPTracker

# Setup Logging
logging.basicConfig(level=logging.INFO, format='[*] %(message)s')
log = logging.getLogger("openclaw_scan")
log.setLevel(logging.INFO)

# Configuration
DEFAULT_TARGETS_FILE = "config/openclaw_targets.txt"
OUTPUT_FILE = "data/openclaw_exposed.csv"
HISTORY_FILE = "data/openclaw_history.csv"

# Vulnerable Versions (Simulated logic per prompt)
VULN_cutoff_date = "2026-01-29"

def load_targets(filepath: str) -> List[str]:
    targets = []
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    return targets

def get_risk_level(banner: Dict, is_corp: bool) -> str:
    """
    Scores risk:
    - Critical: No Auth
    - High: Old Version OR Corporate IP
    - Medium: Auth but exposed
    - Low: Behind tunnel/VPN (hard to detect via Shodan usually, but maybe header clues)
    """
    data = banner.get('data', '') or ''
    title = banner.get('title', '') or ''
    
    # 1. Check Auth
    # OpenClaw returns 401 or "authentication required" if secured.
    # If we see full JSON schema or "gatewayUrl", it's likely unauth.
    no_auth = False
    if "gatewayUrl" in data or "agent_id" in data:
        # Strong indicator of data leakage
        no_auth = True
    if "401 Unauthorized" in data:
        no_auth = False
    
    if no_auth:
        return "CRITICAL"
        
    # 2. Check Version/Corp
    # Shodan doesn't always parse version in 'version' field for custom apps. 
    # We might need regex on banner 'data'.
    # For now, let's assume 'High' if it's Corporate.
    if is_corp:
        return "HIGH"
        
    return "MEDIUM"

def run_scan(api_key: str, targets: List[str], budget_tracker: CreditBudget, cache: ShodanCache):
    try:
        api = shodan.Shodan(api_key)
    except Exception as e:
        log.error(f"Failed to init Shodan API: {e}")
        return []

    # Build Queries
    queries = [
        'port:18789 title:"OpenClaw"',
        'port:18789 title:"Moltbot"',
        'port:18789 title:"Clawdbot"',
        'port:18789 "gateway" "websocket"' # Tier 2
    ]
    
    # Tier 3: Targets
    for t in targets:
        if t.startswith("ASN:"):
            queries.append(f'port:18789 asn:"{t.replace("ASN:", "")}"')
        else:
            queries.append(f'port:18789 org:"{t}"')

    results = {} # ip -> info

    log.info(f"Running {len(queries)} scan queries...")

    for q in queries:
        log.info(f"Querying: {q}")
        
        # Check Cache first
        cache_key = f"openclaw_search:{q}"
        cached_res = cache.get(cache_key, max_age_days=3)
        
        matches = []
        if cached_res:
            log.info("  -> Using cached results.")
            matches = cached_res.get('matches', [])
        else:
            # Check Count first (Cheap check - 1 credit? User said 1 credit. 
            # But Freelancer plan is huge now. We can just skip count and do search? 
            # Prompt asked for Phase 1 Count check.)
            
            # Since user has Freelancer (1M credits), we can be less stingy,
            # BUT we should still stick to the planned architecture.
            
            if not budget_tracker.check_can_spend(1):
                log.warning("Budget exhausted.")
                break
                
            try:
                # Count
                budget_tracker.spend(1)
                count_res = api.count(q)
                total = count_res.get('total', 0)
                log.info(f"  -> Count: {total}")
                
                if total > 0:
                    fetched = 0
                    page = 1
                    
                    # Determine how many to fetch based on global LIMIT arg?
                    # For now, let's keep fetching until we hit budget or run out of results.
                    # Assuming the 'matches' list grows.
                    
                    while True:
                        if not budget_tracker.check_can_spend(1):
                            log.warning("Budget exhausted during pagination.")
                            break
                            
                        # Safety break if we have enough for this query?
                        # Let's limit per-query to 1000 to prevent one query eating everything?
                        if fetched >= 1000: 
                             log.info("  -> Per-query safety limit (1000) reached.")
                             break

                        budget_tracker.spend(1)
                        log.info(f"    Fetching page {page}...")
                        
                        search_res = api.search(q, page=page, limit=100) # limit=100 is just page size
                        batch = search_res.get('matches', [])
                        if not batch:
                            break
                            
                        matches.extend(batch)
                        fetched += len(batch)
                        page += 1
                        time.sleep(1) # Rate limit
                        
                        if fetched >= total:
                            break

                    # Cache the massive result? Might be too big.
                    # Let's cache the summary or just last page? 
                    # For deep pagination, caching the whole list in one blob is dangerous for SQLite size.
                    # We skip full-list caching for deep scans to be safe or cache truncated.
                    if fetched < 500:
                         cache.set(cache_key, {'matches': matches})
            except Exception as e:
                log.error(f"  [!] Error: {e}")
                continue

        # Process Matches
        for m in matches:
            ip = m.get('ip_str')
            if not ip: continue
            
            # Determine if corporate match
            org = m.get('org', '') or ''
            asn = m.get('asn', '') or ''
            is_corp = False
            matched_target = ""
            
            for t in targets:
                clean_t = t.replace("ASN:", "")
                if clean_t.lower() in org.lower() or clean_t in asn:
                    is_corp = True
                    matched_target = t
                    break

            risk = get_risk_level(m, is_corp)
            
            entry = {
                "ip": ip,
                "port": m.get('port'),
                "org": org,
                "asn": asn,
                "country": m.get('location', {}).get('country_name', ''),
                "city": m.get('location', {}).get('city', ''),
                "hostnames": ";".join(m.get('hostnames', [])),
                "product": m.get('product', 'OpenClaw'),
                "version": m.get('version', ''),
                "os": m.get('os', ''),
                "transport": m.get('transport', 'tcp'),
                "has_auth": "False" if risk == "CRITICAL" else "True", # inferred
                "risk_level": risk,
                "query_source": q,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
                "shodan_total": 0, # placeholder
                "data_snippet": (m.get('data') or '')[:50].replace('\n', ' '),
                "is_corporate": str(is_corp),
                "matched_org": matched_target
            }
            results[ip] = entry

    return list(results.values())

def save_active_results(results: List[Dict], filepath: str):
    if not results:
        return
        
    headers = list(results[0].keys())
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(results)
    log.info(f"Saved {len(results)} active instances to {filepath}")


def update_history(current_results: List[Dict], history_file: str):
    # Load History
    history = {} # ip -> record
    if os.path.exists(history_file):
        with open(history_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                history[row['ip']] = row
    
    now_str = datetime.now(timezone.utc).isoformat()
    
    # Process Updates
    for res in current_results:
        ip = res['ip']
        if ip in history:
            # Update seen
            history[ip]['last_seen'] = now_str
            # Update dynamic fields
            history[ip]['risk_level'] = res['risk_level']
            history[ip]['data_snippet'] = res['data_snippet']
        else:
            # New Entry
            res['first_seen'] = now_str
            res['last_seen'] = now_str
            res['days_exposed'] = 0
            history[ip] = res
            
    # Calculate days exposed & write back
    final_rows = []
    for ip, row in history.items():
        # Clean calculation
        try:
            first = datetime.fromisoformat(row['first_seen'])
            last = datetime.fromisoformat(row['last_seen'])
            delta = (last - first).days
            row['days_exposed'] = delta
        except (ValueError, KeyError, TypeError) as e:
            log.warning("Could not calculate days_exposed for IP %s: %s", row.get('ip', 'unknown'), e)
        final_rows.append(row)
        
    if final_rows:
        headers = final_rows[0].keys()
        with open(history_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(final_rows)
            
    log.info(f"Updated history: {len(final_rows)} total tracked instances.")


def main():
    load_dotenv()
    API_KEY = os.getenv("SHODAN_API_KEY")
    if not API_KEY:
        log.error("Error: SHODAN_API_KEY not found in .env")
        sys.exit(1)
        
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", default=DEFAULT_TARGETS_FILE)
    parser.add_argument("--budget", type=int, default=100, help="Credits for this run") 
    # Increased default budget since Freelancer plan
    args = parser.parse_args()
    
    # Init Budget
    budget = CreditBudget()
    budget.set_budget(args.budget)
    
    # Init Cache
    cache = ShodanCache()
    
    # Load Targets
    targets = load_targets(args.targets)
    
    # Run Scan
    active_instances = run_scan(API_KEY, targets, budget, cache)

    # Ensure files exist before saving
    Path(OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    
    if active_instances:
        # Save Snapshot of currently exposed
        save_active_results(active_instances, OUTPUT_FILE)
        # Update Historical Database
        update_history(active_instances, HISTORY_FILE)
        
        # Generate STIX
        try:
            from openclaw_stix import generate_stix_bundle
            generate_stix_bundle(OUTPUT_FILE, "data/openclaw_stix.json")
        except ImportError:
            log.warning("Could not import openclaw_stix. Is stix2 installed?")
        except Exception as e:
            log.error(f"STIX generation failed: {e}")

        log.info(f"Scan complete. Found {len(active_instances)} exposed instances.")
    else:
        log.info("No OpenClaw instances found.")
        
    cache.close()

if __name__ == "__main__":
    main()
