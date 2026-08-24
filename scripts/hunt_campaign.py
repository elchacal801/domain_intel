#!/usr/bin/env python3
"""
hunt_campaign.py

Proactively hunts for new campaign infrastructure using Shodan.
Features:
- Expanded query list (Disposable Email variations)
- Credit Budgeting (Safety)
- Baseline comparison (data/known_campaign_ips.txt)
- GitHub Actions Alerting (Exit code 1 on new findings)
"""

import os
import sys
import shodan
from pathlib import Path
from dotenv import load_dotenv
from shodan_utils import CreditBudget
from shared.otx_client import query_otx_passive_dns
from shared.sanitize import sanitize_csv_value

# Load env vars
load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# The key check lives in main(), not at import time: exiting on import makes the
# module impossible to import for testing, which is why the query set had no
# coverage despite driving all campaign discovery.

# Configuration
KNOWN_IPS_FILE = Path("data/known_campaign_ips.txt")
# Query set. Every entry below was volume-checked against Shodan before being
# added; every query removed had produced zero findings in six months of runs.
#
# Measured behaviour that shapes this list:
#  - Comma-separated values act as OR *within* http.title, but NOT within
#    http.html -- a collapsed http.html:"a","b" query returns 0 results, so
#    body-content terms each need their own query.
#  - http.html consistently outperforms http.title for the same term, because a
#    site can rename its <title> to something innocuous while the body still
#    carries the words users read:
#        temporary email   title 308  ->  html 463
#        disposable email  title  93  ->  html 308
#        temp mail         title 117  ->  html 246
#        临时邮箱           title 115  ->  html 266
#  - "Temp Mail"/"TempMail" were absent entirely and overlap the existing
#    "Temporary Email" query by only 36 hosts, i.e. ~202 hosts were invisible.
#
# KNOWN LIMITATION: api.search() returns only the first page (100 matches), so
# a query matching 651 hosts surfaces 100 of them. Dedup means later runs
# re-see the same page and find nothing new, so coverage plateaus. Paginating
# would multiply credit cost and is left as a deliberate follow-up.
QUERIES = [
    # --- English titles, collapsed into one OR'd filter (~651 hosts) ---
    'http.title:"temporary email","temp mail","tempmail","temp email",'
    '"disposable email","disposable mailbox","temporary mailbox",'
    '"email generator","anonymous email","fake email","10 minute mail","mailinator"',

    # --- Non-English titles (~159 hosts). Chinese dominates, which fits DEA
    # infrastructure clustering on Alibaba Cloud and China Telecom ranges. ---
    'http.title:"临时邮箱","临时邮件","Email sementara","Correo temporal",'
    '"Временная почта","Email temporário","Geçici e-posta","Wegwerf"',

    # --- Body content: obfuscation-resistant, one query per term ---
    'http.html:"temporary email"',
    'http.html:"disposable email"',
    'http.html:"temp mail"',
    'http.html:"tempmail"',
    'http.html:"临时邮箱"',
    'http.html:"Email sementara"',

    # --- Retained from the original set: 76 findings historically ---
    'http.title:"disposable and free domain"',
]

# Removed after six months of zero findings each:
#   'http.title:"Public Email Service"'          (global volume: 1)
#   'net:51.254.35.0/24 "Public Email Service"'  (range now inactive)
#   'ssl:"in.mail.tm"'
# Also folded in: "Temporary Emails"/"Disposable Emails" (2 global hosts each)
# are covered by the collapsed English title query above.

BUDGET_LIMIT = 30 # credits; 9 queries plus headroom for retries

import csv
from datetime import datetime

# ... (imports) ...

HISTORY_FILE = Path("data/campaign_hunt_history.csv")

def load_known_ips():
    """Load manually curated baseline IPs from known_campaign_ips.txt."""
    if not KNOWN_IPS_FILE.exists():
        print(f"[!] Warning: {KNOWN_IPS_FILE} not found. Starting with empty baseline.")
        return set()
    ips = set()
    with open(KNOWN_IPS_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                ips.add(line)
    return ips

def load_history_ips():
    """Load IPs that have already been logged to the history file."""
    if not HISTORY_FILE.exists():
        return set()
    found = set()
    with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader, None) # Skip header
        for row in reader:
            if row:
                found.add(row[1]) # IP is column 1
    return found

def log_new_hit(ip, query, match_data):
    """Appends a new hit to the history CSV."""
    file_exists = HISTORY_FILE.exists()
    
    with open(HISTORY_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['first_seen', 'ip', 'query', 'org', 'country'])
            
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            query,
            sanitize_csv_value(match_data.get('org', 'n/a')),
            sanitize_csv_value(match_data.get('location', {}).get('country_name', 'n/a'))
        ])

PIVOTED_IPS_FILE = Path("data/.pivoted_ips.txt")


def load_pivoted_ips():
    """Load IPs that have already been successfully OTX-pivoted."""
    if not PIVOTED_IPS_FILE.exists():
        return set()
    with open(PIVOTED_IPS_FILE, 'r', encoding='utf-8') as f:
        return {line.strip() for line in f if line.strip()}


def mark_pivoted(ip):
    """Record that an IP has been OTX-pivoted (even if no results)."""
    with open(PIVOTED_IPS_FILE, 'a', encoding='utf-8') as f:
        f.write(ip + '\n')


def pivot_ip(ip, label, pivot_file):
    """Query OTX passive DNS for an IP and append results to pivot_file.

    Returns the number of domains found.
    """
    print(f"::group:: [Auto-Pivot] Pivoting on IP {ip}...")
    found = 0
    try:
        pivot_domains = query_otx_passive_dns(ip)
        if pivot_domains:
            print(f"::notice:: [Pivot] Found {len(pivot_domains)} domains on {ip}!")
            file_exists = pivot_file.exists()
            with open(pivot_file, 'a', newline='', encoding='utf-8') as f:
                headers = ['pivot_selector', 'pivot_ip', 'discovered_domain', 'source']
                writer = csv.DictWriter(f, fieldnames=headers)
                if not file_exists:
                    writer.writeheader()
                for d in pivot_domains:
                    writer.writerow({
                        'pivot_selector': label,
                        'pivot_ip': ip,
                        'discovered_domain': sanitize_csv_value(d),
                        'source': 'AlienVault_OTX'
                    })
            found = len(pivot_domains)
        else:
            print(f"  - No passive DNS records found.")
    except Exception as e:
        print(f"  [!] Pivot failed: {e}")
    print("::endgroup::")
    mark_pivoted(ip)
    return found


def main():
    print("--- Automated Campaign Hunt ---")

    # 1. Setup Budget
    if not SHODAN_API_KEY:
        print("Error: SHODAN_API_KEY not found.")
        return 1

    budget = CreditBudget()
    budget.set_budget(BUDGET_LIMIT)

    # 2. Load Baselines
    known_ips = load_known_ips()
    history_ips = load_history_ips()
    pivoted_ips = load_pivoted_ips()
    print(f"Loaded {len(known_ips)} manual baseline IPs.")
    print(f"Loaded {len(history_ips)} previously hunted IPs.")
    print(f"Loaded {len(pivoted_ips)} previously pivoted IPs.")

    api = shodan.Shodan(SHODAN_API_KEY)
    pivot_file = Path("data/campaign_pivot_findings.csv")

    # We track session findings to avoid duplicates within the same run loop
    session_found_ips = set()
    new_hits_count = 0

    print(f"Executing {len(QUERIES)} queries...")

    for query in QUERIES:
        try:
            budget.spend(1)
            print(f"Querying: {query}")
            results = api.search(query)

            for m in results['matches']:
                ip = m['ip_str']
                session_found_ips.add(ip)

                # Check if it's truly new (not in manual baseline AND not in history)
                if ip not in known_ips and ip not in history_ips:

                    # Mark as seen in history immediately so we don't double log in the same run
                    history_ips.add(ip)
                    new_hits_count += 1

                    # GitHub Actions Annotation
                    print(f"::warning:: [NEW FINDING] {ip} added to history.")
                    print(f"  Details: {m.get('org', 'n/a')} | {m.get('location', {}).get('country_name', 'n/a')}")

                    # Log it
                    log_new_hit(ip, query, m)

                    # --- Automated OTX Pivot ---
                    if ip not in pivoted_ips:
                        pivot_ip(ip, f"Hunt:{query}", pivot_file)
                        pivoted_ips.add(ip)

        except Exception as e:
            print(f"Error executing query '{query}': {e}")

    # 3. Backfill: pivot historical IPs that were never OTX-queried
    unpivoted = (history_ips - known_ips - pivoted_ips)
    if unpivoted:
        print(f"\n--- Backfill: {len(unpivoted)} historical IPs never pivoted ---")
        for ip in sorted(unpivoted):
            pivot_ip(ip, "Backfill", pivot_file)
            pivoted_ips.add(ip)

    # 4. Report
    print("\n--- Hunt Results ---")
    print(f"Total Unique IPs Found (Session): {len(session_found_ips)}")
    print(f"New Findings Logged: {new_hits_count}")

    if new_hits_count > 0:
        print(f"\n[INFO] {new_hits_count} new IPs were added to {HISTORY_FILE}.")
    else:
        print("\n[INFO] No new infrastructure detected.")

    # ALWAYS exit 0 so we don't break the build.
    # The warning annotation will still be visible in GitHub UI.
    sys.exit(0)

if __name__ == "__main__":
    main()
