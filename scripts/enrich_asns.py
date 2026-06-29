import csv
import os
import glob
import time
import json
import urllib.request
import urllib.parse
import urllib.error
import ssl

DATA_DIR = "data"

# Primary: RIPE Stat
RIPE_API_BASE = "https://stat.ripe.net/data/as-overview/data.json?resource=AS"

# Backup: HackerTarget (User requested)
# Note: HackerTarget API free tier might be rate limited or return different formats.
# Using 'aslookup' endpoint.
HT_API_BASE = "https://api.hackertarget.com/aslookup/?q="

def get_column_name(headers, candidates):
    for h in headers:
        if h.lower() in candidates:
            return h
    return None

def fetch_ripe_data(asn):
    """
    Fetches ASN info from RIPE Stat API.
    """
    url = f"{RIPE_API_BASE}{asn}"
    print(f"  [RIPE] Fetching {asn}...")
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(
            url, 
            data=None, 
            headers={'User-Agent': 'DomainIntel/1.0'}
        )
        with urllib.request.urlopen(req, context=context, timeout=10) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                if data.get('status') == 'ok' and 'data' in data:
                    holder = data['data'].get('holder', '')
                    if holder:
                        return {'name': holder, 'source': 'RIPE'}
    except Exception as e:
        print(f"  [RIPE] Error {asn}: {e}")
    return None

def fetch_hackertarget_data(asn):
    """
    Backup: Fetches ASN info from HackerTarget.
    API returns lines: "IP_PREFIX" (usually).
    However, browsing to https://api.hackertarget.com/aslookup/?q=AS15169 returns prefixes.
    If we can't get the name easily, this might be limited.
    BUT, if we query an IP, we get the name.
    """
    # NOTE: HackerTarget free API is limited.
    url = f"{HT_API_BASE}AS{asn}"
    print(f"  [HT] Fetching {asn}...")
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'DomainIntel/1.0'}
        )
        with urllib.request.urlopen(req, context=context, timeout=10) as response:
            if response.status == 200:
                # content is text, lines of prefixes
                # Checking if the response contains metadata? 
                # Currently HT API generic query 'ASxxx' returns prefixes.
                # Without an auth key or premium, 'name' might not be visible easily via this simple endpoint.
                pass
    except Exception as e:
        print(f"  [HT] Error {asn}: {e}")
    return None

def fetch_asn_info(asn):
    # Try RIPE first (Primary)
    info = fetch_ripe_data(asn)
    if info:
        return info
        
    # Try HackerTarget (Backup) - Placeholder for now as mainly prefixes are returned
    # But leaving structure as requested.
    # info = fetch_hackertarget_data(asn)
    # if info: return info
    
    return None

def main():
    files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
    
    # 1. Identify missing ASNs
    missing_asns = set()
    file_headers = {} 
    
    print("Scanning for missing ASN names...")
    for file_path in files:
        with open(file_path, 'r', encoding='utf-8-sig', errors='replace') as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames: continue
            
            headers = reader.fieldnames
            file_headers[file_path] = headers
            
            asn_col = get_column_name(headers, ['asn', 'asn_number'])
            name_col = get_column_name(headers, ['asn_name', 'name'])
            
            if not asn_col or not name_col:
                continue
            
            for row in reader:
                asn_val = row.get(asn_col, '').strip().upper()
                name_val = row.get(name_col, '').strip()
                
                if asn_val.startswith("AS"):
                    clean_asn = asn_val[2:]
                else:
                    clean_asn = asn_val
                
                clean_asn = clean_asn.split(' ')[0]
                
                if clean_asn and clean_asn.isdigit() and not name_val:
                    missing_asns.add(clean_asn)

    print(f"Found {len(missing_asns)} ASNs with missing names.")
    
    if not missing_asns:
        print("No missing names found. Exiting.")
        return

    # 2. Fetch Data
    asn_data_cache = {}
    for i, asn in enumerate(missing_asns):
        info = fetch_asn_info(asn)
        if info and info['name']:
            asn_data_cache[asn] = info
            print(f"  Found: {info['name']} ({info['source']})")
        else:
            print(f"  No data for {asn}")
        
        if i < len(missing_asns) - 1:
            time.sleep(0.5) 

    # 3. Update Files
    print("\nUpdating files...")
    for file_path in files:
        if file_path not in file_headers: continue
        
        filename = os.path.basename(file_path)
        headers = file_headers[file_path]
        asn_col = get_column_name(headers, ['asn', 'asn_number'])
        name_col = get_column_name(headers, ['asn_name', 'name'])
        
        if not asn_col or not name_col:
            continue
            
        updated_rows = []
        modified = False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig', errors='replace') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    asn_raw = row.get(asn_col, '').strip().upper()
                    name_val = row.get(name_col, '').strip()
                    
                    if asn_raw.startswith("AS"):
                        clean_asn = asn_raw[2:]
                    else:
                        clean_asn = asn_raw
                    clean_asn = clean_asn.split(' ')[0]
                    
                    if not name_val and clean_asn in asn_data_cache:
                        new_name = asn_data_cache[clean_asn]['name']
                        if new_name:
                            row[name_col] = new_name
                            modified = True
                            
                    updated_rows.append(row)
            
            if modified:
                print(f"  Updating {filename}...")
                with open(file_path, 'w', encoding='utf-8', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=headers)
                    writer.writeheader()
                    writer.writerows(updated_rows)
        except Exception as e:
            print(f"Error processing {filename}: {e}")

    print("Done.")

if __name__ == "__main__":
    main()
