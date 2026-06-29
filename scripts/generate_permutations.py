#!/usr/bin/env python3
"""
generate_permutations.py

Uses dnstwist to act proactively:
1. Reads domains from data/targets.txt (high value brands).
2. Generates "fuzzed" permutations (lookalikes).
3. Outputs to data/potential_typosquats.csv.
4. (Optional) In the future, we can resolve these to see if they are registered.
"""

import os
import sys
import argparse
import csv
import json
import logging
import subprocess
import dnstwist

# Configure dnstwist logging to be less noisy if needed
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

INPUT_FILE = "data/targets.txt"
OUTPUT_FILE = "data/potential_typosquats.csv"

def load_targets():
    if not os.path.exists(INPUT_FILE):
        return ["example.com"]
    with open(INPUT_FILE, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]


def run_dnstwist(domain):
    """
    Runs dnstwist generation logic via CLI.
    """
    try:
        # We'll use JSON format for easier parsing
        # Use a unique temp file per domain to avoid collision if parallelized later
        import uuid
        temp_json = f"temp_dnstwist_{uuid.uuid4().hex}.json"
        
        # dnstwist CLI:
        # -r: registered only (resolve)
        # -f json: json format
        # -o file: output to file
        # -t 20: threads (lowered to balance with ThreadPoolExecutor)
        cmd = [
            sys.executable, "-m", "dnstwist", 
            "--registered", 
            "--format", "json", 
            "--output", temp_json,
            "--threads", "20",
            domain
        ]
        
        # This will block until finished. Can be slow for large domains.
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        
        if result.returncode != 0:
            logging.warning(f"dnstwist exited with {result.returncode} for {domain}")
            
        data = []
        if os.path.exists(temp_json):
            try:
                with open(temp_json, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except Exception as e:
                logging.error(f"Failed to parse dnstwist output for {domain}: {e}")
            finally:
                os.remove(temp_json)
                
        return data
        
    except Exception as e:
        logging.error(f"Error fuzzing {domain}: {e}")
        return []

import concurrent.futures

def main():
    targets = load_targets()
    logging.info(f"Generating permutations for {len(targets)} targets...")
    
    all_results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_target = {executor.submit(run_dnstwist, target): target for target in targets}
        for i, future in enumerate(concurrent.futures.as_completed(future_to_target)):
            target = future_to_target[future]
            try:
                results = future.result()
                # enrich with source
                for r in results:
                    r['source_target'] = target
                all_results.extend(results)
                logging.info(f"[{i+1}/{len(targets)}] Finished {target}, found {len(results)} permutations.")
            except Exception as e:
                logging.error(f"Target {target} generated an exception: {e}")
        
    logging.info(f"Generated {len(all_results)} permutations.")
    
    # Save to CSV
    if not all_results:
        logging.warning("No results found.")
        return

    keys = set()
    for r in all_results:
        keys.update(r.keys())
    
    fieldnames = sorted(list(keys))
    # Ensure 'domain' is first
    if 'domain' in fieldnames:
        fieldnames.remove('domain')
        fieldnames.insert(0, 'domain')
    
    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for res in all_results:
            writer.writerow(res)
            
    logging.info(f"Saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
