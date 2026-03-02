#!/usr/bin/env python3
"""
ai_typosquat.py

Identifies potential typosquatting domains targeting High Value Targets (Google, Microsoft, Banks, etc.)
using LLM-based semantic similarity and visual homoglyph awareness.
"""

import os
import csv
import argparse
import logging
import sys
from typing import Dict, List, Optional
from dotenv import load_dotenv
from shared.llm_client import LLMClient, load_model_chain

# Load environment variables
load_dotenv()

# LLM Client — uses Haiku-first chain for typosquat detection (cost-optimized)
llm = LLMClient(models=load_model_chain("typosquat"))
logger = logging.getLogger(__name__)
OUTPUT_FILE = "data/ai_typosquats.csv"
INPUT_FILE = "data/triage_candidates.csv" # Default to using the funnel

# High Value Targets to protect
TARGETS = [
    "Google", "Microsoft", "Apple", "Amazon", "Facebook", "Meta", "Netflix",
    "PayPal", "Chase", "Wells Fargo", "Bank of America", "Citi", "Coinbase",
    "Binance", "Outlook", "OneDrive", "Dropbox", "Adobe", "Salesforce",
    "Slack", "Zoom", "Twilio", "Stripe", "Shopify", "Instagram", "TikTok",
    "LinkedIn", "Twitter", "X.com", "Uber", "Airbnb", "Spotify"
]

SYSTEM_PROMPT = f"""
You are a cybersecurity analyst specializing in brand protection.
Your task is to analyze a list of domains and identify if they are 'typosquats' or 'impersonations' of these specific high-value targets:
{', '.join(TARGETS)}.

Look for:
1. Homoglyphs (e.g. 'g00gle', 'rnicrosoft')
2. Typos (e.g. 'googel', 'micorsoft')
3. Combo-squatting (e.g. 'google-security', 'login-microsoft')
4. TLD abuse (e.g. 'google.tk')

Return JSON format only:
{{
    "matches": [
        {{ "domain": "example-google.com", "target": "Google", "reason": "Combo-squatting with security keyword", "confidence": "High" }}
    ]
}}
If no matches, return {{ "matches": [] }}.
"""

# ---------------------------------------------------------------------------
# Algorithmic typosquat pre-scoring
# ---------------------------------------------------------------------------

# Prefixes commonly used in phishing / typosquatting domains
_STRIP_PREFIXES = ("www.", "login.", "secure.", "mail.", "account.", "signin.",
                   "update.", "verify.", "support.", "service.")

# Homoglyph substitution map: suspicious char(s) -> canonical replacement
_HOMOGLYPHS = [
    ("0", "o"),
    ("1", "l"),
    ("1", "i"),
    ("rn", "m"),
    ("vv", "w"),
]


def _strip_domain(domain: str) -> str:
    """Strip TLD and common phishing prefixes from a domain.

    Examples:
        "www.google-login.com"  -> "google-login"
        "login.paypal.co.uk"    -> "paypal"
        "secure.chase.net"      -> "chase"
    """
    domain = domain.lower().strip()

    # Remove TLD: handle multi-part TLDs like .co.uk, .com.au
    # Strategy: split on '.', drop last part (TLD), then check for common
    # second-level country TLDs.
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
        parts = parts[:-2]
    elif len(parts) >= 2:
        parts = parts[:-1]
    domain_base = ".".join(parts)

    # Strip known phishing prefixes
    for prefix in _STRIP_PREFIXES:
        if domain_base.startswith(prefix):
            domain_base = domain_base[len(prefix):]

    return domain_base


def _levenshtein(s: str, t: str) -> int:
    """Compute Levenshtein edit distance between two strings (stdlib only)."""
    n, m = len(s), len(t)
    if n == 0:
        return m
    if m == 0:
        return n

    # Use two-row optimisation to keep memory O(min(n,m))
    if n > m:
        s, t = t, s
        n, m = m, n

    prev = list(range(n + 1))
    curr = [0] * (n + 1)

    for j in range(1, m + 1):
        curr[0] = j
        for i in range(1, n + 1):
            cost = 0 if s[i - 1] == t[j - 1] else 1
            curr[i] = min(
                curr[i - 1] + 1,       # insertion
                prev[i] + 1,           # deletion
                prev[i - 1] + cost,    # substitution
            )
        prev, curr = curr, prev

    return prev[n]


def _apply_homoglyphs(text: str) -> str:
    """Replace common homoglyph characters with their canonical forms."""
    result = text
    for fake, real in _HOMOGLYPHS:
        result = result.replace(fake, real)
    return result


def score_typosquat(domain: str, targets: Optional[List[str]] = None) -> Optional[Dict]:
    """Algorithmically check if *domain* is a likely typosquat of any target brand.

    Returns a match dict (domain, target, reason, confidence) for high-confidence
    algorithmic matches, or ``None`` when the domain should be forwarded to the
    AI for deeper analysis.
    """
    if targets is None:
        targets = TARGETS

    domain_base = _strip_domain(domain)
    if not domain_base:
        return None

    for target in targets:
        target_lower = target.lower()

        # --- 1. Brand substring match (combo-squatting) ---
        if target_lower in domain_base and domain_base != target_lower:
            return {
                "domain": domain,
                "target": target,
                "reason": f"Brand name '{target}' found as substring (combo-squatting)",
                "confidence": "High",
            }

        # --- 2. Exact match after stripping (not a typosquat) ---
        if domain_base == target_lower:
            # The domain *is* the brand — not a typosquat
            continue

        # --- 3. Homoglyph detection ---
        normalised = _apply_homoglyphs(domain_base)
        if normalised == target_lower and normalised != domain_base:
            return {
                "domain": domain,
                "target": target,
                "reason": f"Homoglyph substitution detected (normalises to '{target}')",
                "confidence": "High",
            }
        # Also check if homoglyph-normalised form contains brand
        if target_lower in normalised and normalised != domain_base and domain_base != target_lower:
            return {
                "domain": domain,
                "target": target,
                "reason": f"Homoglyph combo-squat detected (normalises to contain '{target}')",
                "confidence": "High",
            }

        # --- 4. Edit distance (Levenshtein) ---
        distance = _levenshtein(domain_base, target_lower)
        len_diff = abs(len(domain_base) - len(target_lower))
        if distance <= 2 and len_diff <= 3:
            return {
                "domain": domain,
                "target": target,
                "reason": f"Edit distance {distance} from '{target}' (likely typo)",
                "confidence": "High",
            }

    return None


def _load_existing_domains(filepath: str) -> set:
    """Read an existing typosquats CSV and return a set of domain strings."""
    domains = set()
    if not os.path.exists(filepath):
        return domains
    try:
        with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                d = (row.get('domain') or '').strip()
                if d:
                    domains.add(d)
    except Exception as exc:
        logger.warning("Could not read existing output %s: %s", filepath, exc)
    return domains


def read_domains(filepath: str, limit: int = 0) -> List[str]:
    domains = []
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return domains
        
    with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            d = row.get('domain', '').strip()
            if d:
                domains.append(d)
    
    if limit > 0:
        return domains[:limit]
    return domains

def analyze_batch(domains: List[str]) -> List[Dict]:
    if not domains:
        return []

    try:
        domain_list_str = "\n".join(domains)
        
        parsed = llm.complete_json(
            prompt=f"Analyze these domains:\n{domain_list_str}",
            system=SYSTEM_PROMPT
        )
        
        if parsed is None:
            print("[!] All models failed for batch")
            return []
        
        return parsed.get("matches", [])
        
    except Exception as e:
        print(f"Error calling LLM: {e}")
        return []

def save_matches(matches: List[Dict], filepath: str):
    file_exists = os.path.exists(filepath)
    headers = ["domain", "target", "reason", "confidence"]
    
    with open(filepath, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        if not file_exists:
            writer.writeheader()
        
        for m in matches:
            writer.writerow({k: m.get(k, '') for k in headers})

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=INPUT_FILE)
    parser.add_argument("--output", default=OUTPUT_FILE)
    parser.add_argument("--limit", type=int, default=100, help="Max domains to check (cost control)")
    parser.add_argument("--batch-size", type=int, default=20, help="Domains per API call")
    parser.add_argument("--force", action="store_true",
                        help="Re-analyze all domains (ignore previous results)")
    args = parser.parse_args()

    # Using OpenAI Key
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not found in .env")
        sys.exit(1)

    print(f"Reading domains from {args.input}...")
    all_domains = read_domains(args.input, args.limit)
    print(f"Loaded {len(all_domains)} domains to analyze.")

    # Process in batches
    total_matches = 0
    import math
    from tqdm import tqdm

    # --- Delta mode: skip already-analyzed domains ---
    headers = ["domain", "target", "reason", "confidence"]
    if args.force or not os.path.exists(args.output):
        # Force mode or first run: reset file with headers
        with open(args.output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
    else:
        # Delta mode: filter out already-analyzed domains
        existing = _load_existing_domains(args.output)
        all_domains = [d for d in all_domains if d not in existing]
        print(f"Delta mode: {len(existing)} already analyzed, "
              f"{len(all_domains)} new domains to process")
        logger.info("Delta mode: %d already analyzed, %d new domains to process",
                    len(existing), len(all_domains))

    # --- Algorithmic pre-scoring: catch obvious typosquats without AI ---
    algo_matches: List[Dict] = []
    ai_domains: List[str] = []

    for d in all_domains:
        result = score_typosquat(d)
        if result is not None:
            algo_matches.append(result)
        else:
            ai_domains.append(d)

    logger.info("Algorithmic: %d matched, %d remaining for AI",
                len(algo_matches), len(ai_domains))
    print(f"Algorithmic: {len(algo_matches)} matched, "
          f"{len(ai_domains)} remaining for AI")

    # Save algorithmic matches immediately
    if algo_matches:
        save_matches(algo_matches, args.output)
        total_matches += len(algo_matches)

    # Send remaining ambiguous domains to AI in batches
    num_batches = math.ceil(len(ai_domains) / args.batch_size) if ai_domains else 0

    for i in tqdm(range(0, len(ai_domains), args.batch_size), desc="Analyzing Batches"):
        batch = ai_domains[i : i + args.batch_size]
        matches = analyze_batch(batch)
        if matches:
            save_matches(matches, args.output)
            total_matches += len(matches)

    print(f"Done. Found {total_matches} potential typosquats. Saved to {args.output}")

if __name__ == "__main__":
    main()
