import csv

PROBED_FILE = r'data\dea_domains_probed.csv'
MANUAL_FILE = r'data\manual_candidates.csv'

def main():
    # 1. Load Manual Candidates
    manual_domains = set()
    try:
        with open(MANUAL_FILE, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            # Skip header if it exists
            for row in reader:
                if row and row[0] != 'domain':
                    manual_domains.add(row[0].strip().lower())
    except FileNotFoundError:
        print("Manual candidates file not found.")

    print(f"Loaded {len(manual_domains)} manual domains.")

    # 2. Scan Probed Data
    missing_domains = set()
    signature_matches = 0
    
    try:
        with open(PROBED_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            print(f"Columns found: {reader.fieldnames}")
            
            for row in reader:
                domain = row.get('domain', '').strip().lower()
                mx = row.get('primary_mx', '').lower()
                title = row.get('http_title', '')
                
                # Check Signature
                # 1. Title is "Public Email Service"
                # 2. MX contains "in.mail.tm"
                is_match = False
                if title == 'Public Email Service':
                    is_match = True
                elif 'in.mail.tm' in mx:
                    is_match = True
                
                if is_match:
                    signature_matches += 1
                    if domain and domain not in manual_domains:
                        missing_domains.add(domain)

    except FileNotFoundError:
        print("Probed file not found.")
        return

    print(f"Total Signature Matches in Probed Data: {signature_matches}")
    print(f"New Domains Found (Not in Manual List): {len(missing_domains)}")
    
    if signature_matches > 0:
        print("\n--- Sample Matched Domains (Already In Manual List) ---")
        # limit to 10
        count = 0
        # Re-read to print sample because I didn't store them all
        with open(PROBED_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain = row.get('domain', '').strip().lower()
                mx = row.get('primary_mx', '').lower()
                title = row.get('http_title', '')
                a_records = row.get('a_records', 'N/A')
                
                if (title == 'Public Email Service' or 'in.mail.tm' in mx) and domain in manual_domains:
                    print(f"Domain: {domain} | IP: {a_records} | MX: {mx}")
                    count += 1
                    if count >= 10: break

if __name__ == '__main__':
    main()
