#!/usr/bin/env python3
"""
scripts/triage_domains.py

Implements a local "Triage Funnel" to verify generic keyword heuristics + target matching.
This mimics the proposed Daily Workflows without needing GitHub Actions.

Pipeline:
1. Load Domain List (data/dea_domains.csv) - The Haystack.
2. Load Targets (data/targets.txt) - The "Knowns".
3. Load Suspicious Keywords (data/suspicious_keywords.txt) - The "Unknowns".
4. Filter:
    - Priority 1: Direct Target Match (Exact or Typo)
    - Priority 2: Generic Keyword Match (High Intent)
5. Output:
    - data/triage_candidates.csv (The Prioritized List for AI)
    - Stats on reduction (Haystack -> Needle Pile)
"""

import csv
import os
import argparse
import Levenshtein
from typing import List, Set

INPUT_FILE = "data/dea_domains.csv"
OUTPUT_FILE = "data/triage_candidates.csv"
TARGETS_FILE = "data/targets.txt"
KEYWORDS_FILE = "data/suspicious_keywords.txt"

def load_list(filepath: str) -> Set[str]:
    if not os.path.exists(filepath):
        print(f"[!] Missing file: {filepath}")
        return set()
    with open(filepath, 'r', encoding='utf-8') as f:
        return {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}

def load_domains(filepath: str, limit: int = 0) -> List[str]:
    domains = []
    if not os.path.exists(filepath):
        print(f"[!] Missing input: {filepath}")
        return []
    with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
        reader = csv.DictReader(f)
        count = 0
        for row in reader:
            d = row.get('domain', '').strip().lower()
            if d:
                domains.append(d)
                count += 1
                if limit > 0 and count >= limit:
                    break
    return domains

def is_typosquat(domain: str, targets: Set[str]) -> str:
    # 1. Combo check (target in domain)
    for t in targets:
        t_base = t.split('.')[0] # 'amazon' from 'amazon.com'
        if len(t_base) > 3 and t_base in domain and domain != t:
            return f"Combo-squat: {t_base}"
            
    # 2. Levenshtein (Fuzzy)
    # Only check if domain looks somewhat similar length to avoid mass CPU burn
    # This is a simplified check for the demo
    # In prod, use polyleven or efficient sets
    return None

def has_keyword(domain: str, keywords: Set[str]) -> str:
    for k in keywords:
        if k in domain:
            return f"Keyword: {k}"
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=0, help="Limit input domains")
    args = parser.parse_args()

    print("[*] Loading Triage Data...")
    targets = load_list(TARGETS_FILE)
    keywords = load_list(KEYWORDS_FILE)
    domains = load_domains(INPUT_FILE, args.limit)
    
    print(f"    - Targets: {len(targets)}")
    print(f"    - Keywords: {len(keywords)}")
    print(f"    - Input Domains: {len(domains)}")

    candidates = []
    
    print("[*] Running Heuristic Triage...")
    for d in domains:
        reason = None
        priority = 0
        
        # Priority 1: Target Match
        ts_reason = is_typosquat(d, targets)
        if ts_reason:
            reason = ts_reason
            priority = 1
        
        # Priority 2: Keyword Match (if not already found)
        if not reason:
            kw_reason = has_keyword(d, keywords)
            if kw_reason:
                reason = kw_reason
                priority = 2
                
        if reason:
            candidates.append({
                "domain": d,
                "priority": priority,
                "reason": reason
            })

    # Sort by priority (1 is highest)
    candidates.sort(key=lambda x: x['priority'])
    
    print(f"[*] Triage Complete.")
    print(f"    - Total Candidates found: {len(candidates)}")
    print(f"    - Reduction: {len(domains)} -> {len(candidates)} ({len(candidates)/len(domains)*100:.2f}%)")
    
    # Save
    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "priority", "reason"])
        writer.writeheader()
        for c in candidates:
            writer.writerow(c)
            
    print(f"[*] Candidates saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
