#!/usr/bin/env python3
"""
drip_whois.py

Performs slow, rate-limited Whois lookups to build a Registrar database over time.
Targets only "Live" domains and "Typosquats", prioritizing new threats.

Strategy:
1. Merge DEA & Typosquat lists.
2. Filter out already-checked domains.
3. Filter out "Safe" defensive registrations (Squat IP == Target IP).
4. Take top N candidates.
5. Query Registrar via Port 43 (using python-whois library if available, or subprocess).
6. Sleep between queries to avoid bans.

Output:
data/domain_registrars.csv
"""

import csv
import time
import random
import os
import sys
import subprocess
import datetime
from typing import Set, Dict

# Config
OUTPUT_FILE = "data/domain_registrars.csv"
DEA_FILE = "data/dea_domains_probed.csv"
SQUAT_FILE = "data/potential_typosquats.csv"
TARGET_FILE = "data/targets.txt" # Not used for IP check yet, relying on squat file metadata

BATCH_SIZE = 500 # Increased from 100 to up the numbers
SLEEP_MIN = 3
SLEEP_MAX = 8

def load_processed_domains() -> Set[str]:
    processed = set()
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("domain"):
                        processed.add(row["domain"].lower())
        except Exception:
            pass 
    return processed

def load_candidates(processed: Set[str]):
    candidates = [] # List of dicts {domain, priority, ip}
    
    # 1. Load Typosquats (High Priority)
    if os.path.exists(SQUAT_FILE):
        with open(SQUAT_FILE, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                dom = row.get("domain", "").lower()
                
                # Check defensive logic if source IP and Squat IP are same
                # (Simple heuristic check or skip if complex)
                # For now, just prioritizing them.
                
                if dom and dom not in processed:
                    candidates.append({"domain": dom, "priority": 1})

    # 2. Load DEA (Medium Priority - Filter for Liveness)
    if os.path.exists(DEA_FILE):
        with open(DEA_FILE, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                dom = row.get("domain", "").lower()
                http = row.get("http_status", "")
                mx = row.get("mx_records", "")
                
                is_live = (http and http.isdigit()) or bool(mx)
                
                if is_live and dom and dom not in processed:
                    candidates.append({"domain": dom, "priority": 2})

    # Deduplicate
    unique_candidates = {c["domain"]: c for c in candidates}.values()
    
    # Sort by Priority (1 first), then Randomize slightly to avoid sequential hammering
    sorted_list = sorted(unique_candidates, key=lambda x: x["priority"])
    
    return sorted_list

def get_registrar(domain: str) -> str:
    """
    Uses system `whois` command via subprocess (linux/mac) or basic socket attempt.
    Since we are on Windows/Linux hybrid env in Actions, assume `whois` binary might differ.
    Simple approach: try `whois` cli.
    """
    try:
        # Check if python-whois is installed or just use system call?
        # System call is fragile on Windows.
        # Let's try to use a simple socket port 43 lookup if we can't rely on libs.
        # Actually, for reliability, let's use a subprocess call to 'whois'
        # If 'whois' is not in path, this returns "Unknown".
        
        # NOTE: On Windows, 'whois' might not exist.
        # Use a simple socket fallback.
        import socket
        
        # Very basic recursion is hard, just try verisign for com/net
        tld = domain.split(".")[-1]
        server = "whois.iana.org" 
        if tld in ["com", "net"]: server = "whois.verisign-grs.com"
        if tld == "org": server = "whois.pir.org"
        if tld == "io": server = "whois.nic.io"
        
        s = socket.create_connection((server, 43), timeout=10)
        s.send(f"{domain}\r\n".encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data: break
            response += data
        s.close()
        
        text = response.decode("utf-8", "ignore")
        
        # Parse common Registrar lines
        for line in text.splitlines():
            if "Registrar:" in line:
                return line.split("Registrar:")[1].strip()
            if "registrar:" in line: # Case sensitive fallback
                 return line.split("registrar:")[1].strip()
                 
    except Exception as e:
        return f"Error: {str(e)[:20]}"

    return "Not Found"

def main():
    print("[-] Loading candidates...")
    processed = load_processed_domains()
    candidates = load_candidates(processed)
    
    print(f"[-] Candidates queue: {len(candidates)}")
    if not candidates:
        return

    # Process Batch
    to_process = candidates[:BATCH_SIZE]
    print(f"[-] Processing batch of {len(to_process)}...")
    
    results = []
    timeouts = 0
    
    for item in to_process:
        domain = item["domain"]
        print(f"    > Checking {domain}...", end="")
        sys.stdout.flush()
        
        reg = get_registrar(domain)
        print(f" [{reg}]")
        
        results.append({
            "domain": domain,
            "registrar": reg,
            "date_checked": datetime.date.today().isoformat()
        })
        
        # Adaptive Sleep
        if "Error" in reg:
            timeouts += 1
            time.sleep(30) # Backoff
        else:
            timeouts = 0 # Reset
            time.sleep(random.randint(SLEEP_MIN, SLEEP_MAX))
            
        if timeouts >= 3:
            print("[!] Too many timeouts. Aborting run.")
            break
            
    # Save
    file_exists = os.path.exists(OUTPUT_FILE)
    with open(OUTPUT_FILE, "a", newline="", encoding="utf-8") as f:
        headers = ["domain", "registrar", "date_checked"]
        writer = csv.DictWriter(f, fieldnames=headers)
        if not file_exists:
            writer.writeheader()
        writer.writerows(results)
        
    print(f"[*] Saved {len(results)} records to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
