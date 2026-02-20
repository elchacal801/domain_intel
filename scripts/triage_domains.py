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
import logging
import os
import argparse
import Levenshtein
import yaml
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)

INPUT_FILE = "data/dea_domains.csv"
OUTPUT_FILE = "data/triage_candidates.csv"
TARGETS_FILE = "data/targets.txt"
KEYWORDS_FILE = "data/suspicious_keywords.txt"
CLASSIFICATION_FILE = "data/ai_classifications.csv"
FLAME_RULES_FILE = "config/flame_detection_rules.yaml"

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


def load_flame_tp_ids() -> Dict[str, str]:
    """Load FLAME TP ID mappings from ai_classifications.csv if available.

    Returns:
        Dict mapping domain -> comma-separated FLAME TP IDs.
    """
    mapping: Dict[str, str] = {}
    if not os.path.exists(CLASSIFICATION_FILE):
        return mapping
    try:
        with open(CLASSIFICATION_FILE, "r", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                tp_ids = row.get("flame_tp_ids", "").strip()
                if tp_ids:
                    mapping[row.get("domain", "").strip().lower()] = tp_ids
    except (IOError, csv.Error) as exc:
        logger.warning("Could not load FLAME TP IDs: %s", exc)
    return mapping

def load_flame_detection_rules() -> List[Dict[str, Any]]:
    """Load FLAME-derived detection rules from config if available.

    Returns:
        List of enabled rule dicts with patterns to match against domains.
    """
    if not os.path.exists(FLAME_RULES_FILE):
        return []
    try:
        with open(FLAME_RULES_FILE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not data or "rules" not in data:
            return []
        enabled = [r for r in data["rules"] if r.get("enabled", False)]
        if enabled:
            logger.info("Loaded %d enabled FLAME detection rules", len(enabled))
        return enabled
    except (IOError, yaml.YAMLError) as exc:
        logger.warning("Could not load FLAME detection rules: %s", exc)
        return []


def apply_flame_rules(domain: str, domain_data: Dict[str, str],
                      rules: List[Dict[str, Any]]) -> str:
    """Check if a domain matches any FLAME detection rule.

    Args:
        domain: The domain name to check.
        domain_data: Dict of domain metadata (e.g. from CSV row).
        rules: List of enabled FLAME detection rule dicts.

    Returns:
        Match reason string or empty string if no match.
    """
    for rule in rules:
        for pattern in rule.get("patterns", []):
            field = pattern.get("field", "")
            op = pattern.get("operator", "")
            value = pattern.get("value", "")

            # Get the field value to check
            check_value = ""
            if field == "domain":
                check_value = domain
            elif field in domain_data:
                check_value = domain_data.get(field, "")
            else:
                continue

            matched = False
            if op == "contains" and value.lower() in check_value.lower():
                matched = True
            elif op == "equals" and check_value.lower() == value.lower():
                matched = True

            if matched:
                rule_id = rule.get("rule_id", "unknown")
                tp_id = rule.get("source_tp", "unknown")
                logger.info("FLAME rule triggered: %s (from %s) on %s [%s=%s]",
                            rule_id, tp_id, domain, field, value)
                return f"FLAME-RULE:{rule_id}:{tp_id}"

    return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=0, help="Limit input domains")
    args = parser.parse_args()

    print("[*] Loading Triage Data...")
    targets = load_list(TARGETS_FILE)
    keywords = load_list(KEYWORDS_FILE)
    domains = load_domains(INPUT_FILE, args.limit)
    flame_map = load_flame_tp_ids()
    flame_rules = load_flame_detection_rules()
    
    print(f"    - Targets: {len(targets)}")
    print(f"    - Keywords: {len(keywords)}")
    print(f"    - Input Domains: {len(domains)}")
    if flame_map:
        print(f"    - FLAME TP mappings: {len(flame_map)}")
    if flame_rules:
        print(f"    - FLAME detection rules: {len(flame_rules)}")

    candidates = []
    
    print("[*] Running Heuristic Triage...")
    for d in domains:
        reason = None
        priority = 0
        flame_tp_ids = flame_map.get(d, "")
        
        # Priority 0: FLAME TP match (highest)
        if flame_tp_ids:
            reason = f"FLAME:{flame_tp_ids}"
            priority = 0
        
        # Priority 0: FLAME detection rule match
        if not reason and flame_rules:
            rule_reason = apply_flame_rules(d, {}, flame_rules)
            if rule_reason:
                reason = rule_reason
                priority = 0
        
        # Priority 1: Target Match
        if not reason:
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
                "reason": reason,
                "flame_tp_ids": flame_tp_ids,
            })

    # Sort by priority (0 is highest)
    candidates.sort(key=lambda x: x['priority'])
    
    print(f"[*] Triage Complete.")
    print(f"    - Total Candidates found: {len(candidates)}")
    if len(domains) > 0:
        print(f"    - Reduction: {len(domains)} -> {len(candidates)} ({len(candidates)/len(domains)*100:.2f}%)")
    
    # Save
    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "priority", "reason", "flame_tp_ids"])
        writer.writeheader()
        for c in candidates:
            writer.writerow(c)
            
    print(f"[*] Candidates saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
