import csv
import collections

input_file = "data/dea_domains_probed.csv"

def is_live(row):
    # Criteria for "Live":
    # 1. Has HTTP Status (webserver responded)
    # 2. OR Has MX Records (mailserver active)
    
    http = row.get("http_status", "").strip()
    https = row.get("https_status", "").strip()
    mx = row.get("mx_records", "").strip()
    
    # Check if we got any response code that isn't an error
    web_active = False
    if http and http.isdigit(): web_active = True
    if https and https.isdigit(): web_active = True
    
    email_active = bool(mx)
    
    return web_active or email_active

try:
    total = 0
    live_count = 0
    
    with open(input_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1
            if is_live(row):
                live_count += 1
                
    print(f"Total Domains: {total}")
    print(f"Live Domains: {live_count} ({live_count/total*100:.1f}%)")
    print(f"Dead/Inactive: {total - live_count}")

except Exception as e:
    print(f"Error: {e}")
