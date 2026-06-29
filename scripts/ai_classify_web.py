#!/usr/bin/env python3
"""
ai_classify_web.py

Classifies probed web content (Titles + Server Headers) into categories like:
- Phishing / Impersonation
- Legitimate / Business
- Parked / For Sale
- Error / Dead
- C2 / Cobalt Strike / Malware Panel
- Default Page / Unconfigured
"""

import os
import csv
import argparse
import logging
import sys
import re
from typing import List, Dict, Optional
from dotenv import load_dotenv
from shared.llm_client import LLMClient, load_model_chain
from shared.flame_client import get_tp_summaries_for_prompt

# Load environment variables
load_dotenv()

# LLM Client — uses Haiku-first chain for classification (cost-optimized)
llm = LLMClient(models=load_model_chain("classification"))
logger = logging.getLogger(__name__)
OUTPUT_FILE = "data/ai_classifications.csv"
INPUT_FILE = "data/dea_domains_probed.csv" # Must use probed CSV (has title/status/server columns)

# Classification Taxonomy
CATEGORIES = [
    "Phishing", "Legitimate", "Parked", "Error", "C2", "Default", "Unknown"
]

SYSTEM_PROMPT = """
You are a threat intelligence classifier. 
Your input is a list of web page metadata (URL, Title, HTTP Status, Server Header).
Your task is to classify each page into exactly one of these categories:
- Phishing (Impersonating a brand, login pages on suspicious domains)
- Legitimate (Normal business sites, blogs)
- Parked (Domain for sale, goDaddy placeholder, 'Coming Soon')
- Error (403 Forbidden, 404 Not Found, 500 error pages only if explicit in title)
- C2 (Command and Control panels, minimal titles like 'Index of /', suspicious/random titles)
- Default (Apache/Nginx default pages, 'It Works!')

Return JSON format only:
{
    "classifications": [
        { "domain": "login-microsoft.com", "category": "Phishing", "reason": "Login title on non-MS domain", "confidence": "High", "flame_tp_ids": "TP-0001", "flame_confidence": "high" }
    ]
}

For flame_tp_ids: map each domain to zero or more FLAME Threat Path IDs from the taxonomy below (comma-separated). Use empty string if no match.
For flame_confidence: rate your confidence in the FLAME mapping as high, medium, or low. Use empty string if no FLAME match.
"""

# ---------------------------------------------------------------------------
# Rule-based pre-filter — classifies obvious cases without using the LLM
# ---------------------------------------------------------------------------

# Parked-domain title keywords (checked case-insensitively)
_PARKED_PATTERNS: List[str] = [
    "parked", "for sale", "domain for sale", "coming soon",
    "under construction", "buy this domain", "this domain",
    "is available", "godaddy", "namecheap parking", "sedoparking",
    "hugedomains", "dan.com", "afternic",
]

# Default-page title keywords (checked case-insensitively)
_DEFAULT_TITLE_PATTERNS: List[str] = [
    "welcome to nginx", "apache2 ubuntu", "it works", "test page",
    "iis windows", "default web page", "congratulations",
    "welcome to centos",
]

# Server headers that indicate an unconfigured default when title is empty
_DEFAULT_SERVER_NAMES: List[str] = [
    "nginx", "apache", "microsoft-iis", "lighttpd", "litespeed",
    "caddy", "openresty",
]

# Error-page title phrases (checked case-insensitively)
_ERROR_TITLE_PHRASES: List[str] = [
    "403 forbidden", "404 not found", "500 internal",
    "502 bad gateway", "503 service unavailable", "access denied",
]


def _make_result(domain: str, category: str, reason: str,
                 confidence: str) -> Dict:
    """Build a classification result dict with empty FLAME fields."""
    return {
        "domain": domain,
        "category": category,
        "reason": reason,
        "confidence": confidence,
        "flame_tp_ids": "",
        "flame_confidence": "",
    }


def classify_rules(item: Dict) -> Optional[Dict]:
    """Attempt to classify *item* using deterministic rules.

    Returns a classification dict if a rule matches, or ``None`` when the
    item should be forwarded to the LLM for analysis.
    """
    domain = item.get("domain", "")
    title = (item.get("title") or "").strip()
    server = (item.get("server") or "").strip()
    status = (item.get("status") or "").strip()
    title_lower = title.lower()
    server_lower = server.lower()

    # --- Rule 1: Error (HTTP 4xx/5xx or error title phrases) ---
    if status.isdigit() and 400 <= int(status) <= 599:
        return _make_result(domain, "Error",
                            f"HTTP {status} status", "High")

    for phrase in _ERROR_TITLE_PHRASES:
        if phrase in title_lower:
            return _make_result(domain, "Error",
                                f"Title matches error phrase: {phrase}",
                                "High")

    # --- Rule 2: Unknown (completely empty probing data) ---
    if not status and not title and not server:
        return _make_result(domain, "Unknown",
                            "No HTTP status, title, or server header",
                            "Medium")

    # --- Rule 3: Parked ---
    for pattern in _PARKED_PATTERNS:
        if pattern in title_lower:
            return _make_result(domain, "Parked",
                                f"Title matches parked domain pattern: {pattern}",
                                "High")

    # --- Rule 4: Default page ---
    for pattern in _DEFAULT_TITLE_PATTERNS:
        if pattern in title_lower:
            return _make_result(domain, "Default",
                                f"Title matches default page pattern: {pattern}",
                                "High")

    # Server-only default: known server header with empty title
    if not title and server_lower:
        for srv_name in _DEFAULT_SERVER_NAMES:
            if srv_name in server_lower:
                return _make_result(
                    domain, "Default",
                    f"Default server ({server}) with no page title", "High")

    # --- Rule 5: C2 indicators ---
    if title == "Index of /":
        return _make_result(domain, "C2",
                            "Title is 'Index of /' (directory listing)",
                            "Medium")

    # Empty title + status 200 + suspicious server patterns
    if not title and status == "200" and server_lower:
        # Cobalt Strike, Meterpreter, and other unusual servers
        suspicious_re = re.compile(
            r"cobalt|meterpreter|empire|covenant|sliver|havoc|posh",
            re.IGNORECASE,
        )
        if suspicious_re.search(server):
            return _make_result(
                domain, "C2",
                f"Suspicious server header ({server}) with empty title",
                "Medium")

    # No rule matched — needs LLM analysis
    return None


def _load_existing_domains(filepath: str) -> set:
    """Read an existing classifications CSV and return a set of domain strings."""
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


def read_probed_domains(filepath: str, limit: int = 0) -> List[Dict]:
    data = []
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return data
        
    with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Only classify if we have a title or interesting http status
            title = row.get('http_title', '').strip() or row.get('https_title', '').strip()
            server = row.get('http_server', '').strip() or row.get('https_server', '').strip()
            status = row.get('http_status', '') or row.get('https_status', '')
            
            if title or (status == '200' and server):
                row_lite = {
                    "domain": row.get('domain'),
                    "title": title[:200], # Limit length
                    "server": server,
                    "status": status
                }
                data.append(row_lite)
    
    if limit > 0:
        return data[:limit]
    return data

def classify_batch(items: List[Dict], flame_taxonomy: str = "") -> List[Dict]:
    if not items:
        return []

    # Format input for LLM to be concise
    prompt_lines = []
    for item in items:
        line = f"Domain: {item['domain']} | Status: {item['status']} | Title: {item['title']} | Server: {item['server']}"
        prompt_lines.append(line)
        
    prompt_str = "\n".join(prompt_lines)

    # Inject FLAME taxonomy into system prompt if available
    system = SYSTEM_PROMPT
    if flame_taxonomy:
        system = f"{SYSTEM_PROMPT}\n\n{flame_taxonomy}"

    try:
        parsed = llm.complete_json(
            prompt=f"Classify this batch:\n{prompt_str}",
            system=system
        )
        
        if parsed is None:
            logger.warning("All models failed for batch")
            return []
        
        return parsed.get("classifications", [])
        
    except Exception as e:
        logger.error("Error calling LLM: %s", e)
        return []

def save_results(results: List[Dict], filepath: str):
    file_exists = os.path.exists(filepath)
    headers = ["domain", "category", "reason", "confidence", "flame_tp_ids", "flame_confidence"]
    
    with open(filepath, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        if not file_exists:
            writer.writeheader()
        
        for r in results:
            writer.writerow({k: r.get(k, '') for k in headers})

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=INPUT_FILE)
    parser.add_argument("--output", default=OUTPUT_FILE)
    parser.add_argument("--limit", type=int, default=100, help="Max pages to check")
    parser.add_argument("--batch-size", type=int, default=10, help="Items per API call")
    parser.add_argument("--force", action="store_true",
                        help="Re-classify all domains (ignore previous results)")
    args = parser.parse_args()

    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not found in .env")
        sys.exit(1)

    # Load FLAME threat-path taxonomy for prompt injection
    flame_taxonomy = ""
    try:
        flame_taxonomy = get_tp_summaries_for_prompt()
        if flame_taxonomy:
            logger.info("Loaded FLAME taxonomy (%d chars)", len(flame_taxonomy))
        else:
            logger.info("FLAME taxonomy unavailable — classifying without TP mapping")
    except Exception as exc:
        logger.warning("Failed to load FLAME taxonomy: %s", exc)

    print(f"Reading probed data from {args.input}...")
    items = read_probed_domains(args.input, args.limit)
    print(f"Found {len(items)} items with content to classify.")

    # --- Delta mode: skip already-classified domains ---
    headers = ["domain", "category", "reason", "confidence", "flame_tp_ids", "flame_confidence"]
    if args.force or not os.path.exists(args.output):
        # Force mode or first run: reset file with headers
        with open(args.output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
    else:
        # Delta mode: filter out already-classified domains
        existing = _load_existing_domains(args.output)
        items = [it for it in items if it.get("domain") not in existing]
        print(f"Delta mode: {len(existing)} already classified, "
              f"{len(items)} new domains to process")
        logger.info("Delta mode: %d already classified, %d new domains to process",
                    len(existing), len(items))

    # --- Rule-based pre-filter: classify obvious cases without the LLM ---
    rule_results = []
    ai_items = []
    for item in items:
        result = classify_rules(item)
        if result is not None:
            rule_results.append(result)
        else:
            ai_items.append(item)

    if rule_results:
        save_results(rule_results, args.output)

    logger.info("Rule-based: %d classified, %d remaining for AI analysis",
                len(rule_results), len(ai_items))
    print(f"Rule-based: {len(rule_results)} classified, "
          f"{len(ai_items)} remaining for AI analysis")

    import math
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from tqdm import tqdm

    total_classified = len(rule_results)

    # Process remaining items in batches concurrently (LIMIT to 3 workers for Tier 1 API limits)
    if ai_items:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            for i in range(0, len(ai_items), args.batch_size):
                batch = ai_items[i : i + args.batch_size]
                futures.append(executor.submit(classify_batch, batch, flame_taxonomy))

            for future in tqdm(as_completed(futures), total=len(futures), desc="Classifying batches"):
                try:
                    results = future.result()
                    if results:
                        save_results(results, args.output)
                        total_classified += len(results)
                except Exception as e:
                    print(f"Batch failed: {e}")

    print(f"Done. Classified {total_classified} domains. Saved to {args.output}")

if __name__ == "__main__":
    main()
