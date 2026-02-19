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
from typing import List, Dict
from dotenv import load_dotenv
from shared.llm_client import LLMClient
from shared.flame_client import get_tp_summaries_for_prompt

# Load environment variables
load_dotenv()

# LLM Client — uses centralized model chain from shared/llm_client.py
llm = LLMClient()
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

    # Reset/Init output
    headers = ["domain", "category", "reason", "confidence", "flame_tp_ids", "flame_confidence"]
    with open(args.output, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()

    import math
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from tqdm import tqdm
    
    total_classified = 0
    
    # Process batches concurrently (LIMIT to 3 workers for Tier 1 API limits)
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        for i in range(0, len(items), args.batch_size):
            batch = items[i : i + args.batch_size]
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
