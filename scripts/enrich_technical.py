import argparse
import csv
import dns.resolver
import dns.exception
import ssl
import socket
import requests
import imagehash
from PIL import Image
from io import BytesIO
import concurrent.futures
import time
import os
from urllib.parse import urlparse

# Configuration
INPUT_FILE = 'data/triage_candidates.csv'
OUTPUT_FILE = 'data/enriched_candidates.csv'
MAX_WORKERS = 10
TIMEOUT = 5

def extract_soa_email(domain):
    """Extracts the Responsible Person email from the SOA record."""
    try:
        answers = dns.resolver.resolve(domain, 'SOA', lifetime=TIMEOUT)
        for rdata in answers:
            rname = rdata.rname.to_text().rstrip('.')
            # Convert DNS encoded email (hostmaster.example.com) to standard email
            if '.' in rname:
                parts = rname.split('.')
                email = f"{parts[0]}@{'.'.join(parts[1:])}"
                return email
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.resolver.Timeout, dns.exception.DNSException):
        pass
    return None

def extract_ssl_data(domain):
    """Extracts Organization and Serial Number from SSL Certificate."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # We just want the cert, even if invalid
    
    try:
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extract Subject Org
                subject = dict(x[0] for x in cert.get('subject', []))
                org = subject.get('organizationName')
                
                # Extract Serial
                serial = cert.get('serialNumber')
                
                return org, serial
    except (socket.timeout, socket.error, ssl.SSLError, OSError):
        return None, None

def get_favicon_hash(domain):
    """Calculates the perceptual hash of the domain's favicon."""
    try:
        # Try standard location
        url = f"http://{domain}/favicon.ico"
        response = requests.get(url, timeout=TIMEOUT, stream=True)
        if response.status_code == 200:
            img = Image.open(BytesIO(response.content))
            return str(imagehash.phash(img))
    except (requests.RequestException, IOError, OSError):
        pass
    return None

def process_domain(row):
    """Enriches a single domain row."""
    domain = row['domain']
    
    # 1. DNS SOA Email
    soa_email = extract_soa_email(domain)
    
    # 2. SSL Data
    ssl_org, ssl_serial = extract_ssl_data(domain)
    
    # 3. Favicon Hash
    visual_hash = get_favicon_hash(domain)
    
    return {
        **row,
        'soa_email': soa_email or '',
        'ssl_org': ssl_org or '',
        'ssl_serial': ssl_serial or '',
        'visual_hash': visual_hash or ''
    }

def main():
    parser = argparse.ArgumentParser(description="Enrich domains with technical details (SOA, SSL, Favicon).")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of domains to process")
    parser.add_argument("--workers", type=int, default=50, help="Number of concurrent workers")
    args = parser.parse_args()

    print(f"[*] Starting Enrichment on {INPUT_FILE}...")
    
    if not os.path.exists(INPUT_FILE):
        print(f"[!] Input file {INPUT_FILE} not found.")
        return

    domains = []
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        domains = list(reader)
    
    if not domains:
        print("[!] No domains to process.")
        return

    if args.limit > 0:
        print(f"[*] Limiting processing to first {args.limit} domains.")
        domains = domains[:args.limit]

    enriched_results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_domain = {executor.submit(process_domain, row): row for row in domains}
        
        for future in concurrent.futures.as_completed(future_to_domain):
            try:
                data = future.result()
                enriched_results.append(data)
                if len(enriched_results) % 10 == 0:
                    print(f"[*] Processed {len(enriched_results)}/{len(domains)} domains...")
            except Exception as e:
                print(f"[!] Error processing domain: {e}")

    # Write output
    fieldnames = list(domains[0].keys()) + ['soa_email', 'ssl_org', 'ssl_serial', 'visual_hash']
    
    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(enriched_results)
        
    print(f"[+] Enrichment complete. Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
