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
import logging
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
    Runs dnstwist generation logic.
    """
    try:
        # dnstwist python usage is a bit constrained, usually CLI is preferred.
        # But we can instantiate the class.
        
        # Note: dnstwist structure changes often. This assumes v2.x API or similar.
        # If import fails, we might shell out.
        
        fuzzer = dnstwist.DomainFuzzer(domain)
        fuzzer.generate()
        return fuzzer.domains # List of dicts
        
    except Exception as e:
        logging.error(f"Error fuzzing {domain}: {e}")
        return []

def main():
    targets = load_targets()
    logging.info(f"Generating permutations for {len(targets)} targets...")
    
    all_results = []
    
    for target in targets:
        logging.info(f"Fuzzing {target}...")
        results = run_dnstwist(target)
        # enrich with source
        for r in results:
            r['source_target'] = target
        all_results.extend(results)
        
    logging.info(f"Generated {len(all_results)} permutations.")
    
    # Save to CSV
    # dnstwist returns keys like: {'domain-name': '...', 'fuzzer': '...'}
    keys = ['domain-name', 'fuzzer', 'source_target']
    
    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
        writer.writeheader()
        for res in all_results:
            writer.writerow(res)
            
    logging.info(f"Saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
