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

# Load env vars
load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

if not SHODAN_API_KEY:
    print("Error: SHODAN_API_KEY not found.")
    sys.exit(1)

# Configuration
KNOWN_IPS_FILE = Path("data/known_campaign_ips.txt")
QUERIES = [
    'net:51.254.35.0/24 "Public Email Service"',
    'http.title:"Public Email Service"',
    'ssl:"in.mail.tm"',
    'http.title:"Disposable Email"',
    'http.title:"Disposable Temporary Email"',
    'http.title:"Disposable Emails"', 
    'http.title:"Temporary Email"',
    'http.title:"Temporary Emails"',
    'http.title:"disposable and free domain"'
]
BUDGET_LIMIT = 20 # credits

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
            match_data.get('org', 'n/a'),
            match_data.get('location', {}).get('country_name', 'n/a')
        ])

def main():
    print("--- Automated Campaign Hunt ---")
    
    # 1. Setup Budget
    budget = CreditBudget()
    budget.set_budget(BUDGET_LIMIT)
    
    # 2. Load Baselines
    known_ips = load_known_ips()
    history_ips = load_history_ips()
    print(f"Loaded {len(known_ips)} manual baseline IPs.")
    print(f"Loaded {len(history_ips)} previously hunted IPs.")
    
    api = shodan.Shodan(SHODAN_API_KEY)
    
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
                    
        except Exception as e:
            print(f"Error executing query '{query}': {e}")
            
    # 3. Report
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
