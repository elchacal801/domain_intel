import csv
import json
import logging
import os
import requests
import time
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

# ... (Imports remain same) ...
# Configuration
INPUT_FILE = 'data/enriched_candidates.csv'
OUTPUT_FILE = 'data/pivot_discovery.csv'
HISTORY_FILE = 'data/history_pivots.json'
WHOXY_API_KEY = os.getenv("WHOXY_API_KEY")
WHOXY_API_URL = "http://api.whoxy.com/"

# QUOTA PROTECTION
DAILY_LIMIT = 5  # Only 5 queries/day to save 500 credit quota

# Emails to ignore (Generic/Privacy services)
IGNORE_EMAILS = {
    "abuse@cloudflare.com", "dns@cloudflare.com", "hostmaster@cloudflare.com",
    "domains@cloudflare.com", "support@cloudflare.com",
    "abuse@godaddy.com", "hostmaster@godaddy.com",
    "domainsbyproxy.com", "contact@privacyprotect.org",
    "hostmaster@google.com", "dns-admin@google.com",
    "hostmaster@123-reg.co.uk", "domain-admin@wix.com",
    "abuse@namecheap.com", "legal@namecheap.com"
}

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                return set(json.load(f))
        except (json.JSONDecodeError, TypeError, OSError) as e:
            logger.warning("Failed to load history file %s: %s", HISTORY_FILE, e)
            return set()
    return set()

def save_history(history_set):
    with open(HISTORY_FILE, 'w') as f:
        json.dump(list(history_set), f)

def get_reverse_whois(email):
    """Query Whoxy for domains registered to this email."""
    if not email or '@' not in email:
        return []
    
    params = {
        'key': WHOXY_API_KEY,
        'reverse': 'whois',
        'email': email,
        'mode': 'micro' # fast/cheap mode
    }
    
    try:
        response = requests.get(WHOXY_API_URL, params=params, timeout=15)
        if response.status_code == 200:
            data = response.json()
            results = data.get('search_result', [])
            return [res.get('domain_name') for res in results if res.get('domain_name')]
        else:
            print(f"[!] Error {response.status_code} querying {email}")
            return []
    except Exception as e:
        print(f"[!] Exception querying {email}: {e}")
        return []

def main():
    if not WHOXY_API_KEY:
        print("[!] WHOXY_API_KEY not found in .env")
        return

    if not os.path.exists(INPUT_FILE):
        print(f"[!] Input file {INPUT_FILE} not found. Run enrich_technical.py first.")
        return

    print(f"[*] Starting Infrastructure Pivot (Whoxy)...")
    print(f"[*] Strict Limit: {DAILY_LIMIT} API calls per run to conserve quota.")
    
    # 0. Load History (Previous queries)
    history = load_history()
    
    # 1. Prioritize Targets
    # Count frequency of each email in our bad list. 
    # Logic: An email linked to 50 bad domains is a better pivot than one linked to 1.
    email_counts = {}
    
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            email = row.get('soa_email', '').lower().strip()
            if email and '@' in email and email not in IGNORE_EMAILS:
                email_counts[email] = email_counts.get(email, 0) + 1
    
    # Sort by count (Desc) -> Best targets first
    sorted_emails = sorted(email_counts.items(), key=lambda x: x[1], reverse=True)
    
    print(f"[*] Found {len(sorted_emails)} unique candidate emails.")
    
    # 2. Query API (Approximating best bang for buck)
    all_pivots = []
    queries_made = 0
    
    for email, count in sorted_emails:
        if queries_made >= DAILY_LIMIT:
            print("[*] Daily quota limit reached. Stopping.")
            break
            
        if email in history:
            # Skip if we already pivoted on this email (save credits)
            continue
            
        print(f"[{queries_made+1}/{DAILY_LIMIT}] Pivoting on: {email} (Seen {count} times in dataset)...")
        
        domains = get_reverse_whois(email)
        queries_made += 1
        history.add(email) # Mark as seen regardless of result to avoid infinite retry loops on empty results
        
        if domains:
            print(f"    + Found {len(domains)} NEW domains!")
            for domain in domains:
                all_pivots.append({
                    'pivot_selector': email,
                    'pivot_type': 'soa_email',
                    'discovered_domain': domain,
                    'source': 'Whoxy'
                })
        else:
             print("    - No additional domains found.")
        
        # Rate limit
        time.sleep(1)

    # 3. Save Results
    if all_pivots:
        print(f"[*] Saving {len(all_pivots)} discovered domains to {OUTPUT_FILE}...")
        # Start file fresh or append? Usually fresh for daily discovery, 
        # but merge_lists handles aggregation. Let's overwrite for daily slice.
        keys = ['pivot_selector', 'pivot_type', 'discovered_domain', 'source']
        with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(all_pivots)
            
    # Save history
    save_history(history)

if __name__ == "__main__":
    main()
