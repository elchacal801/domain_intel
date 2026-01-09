#!/usr/bin/env python3
"""
ai_typosquat.py

Identifies potential typosquatting domains targeting High Value Targets (Google, Microsoft, Banks, etc.)
using LLM-based semantic similarity and visual homoglyph awareness.
"""

import os
import csv
import argparse
import sys
from typing import List, Dict
from dotenv import load_dotenv
from litellm import completion

# Load environment variables
load_dotenv()

# Constants
# Switching to OpenAI for reliability during test
MODEL = "gpt-4o-mini" 
OUTPUT_FILE = "data/ai_typosquats.csv"
INPUT_FILE = "data/dea_domains.csv"

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
        response = completion(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze these domains:\n{domain_list_str}"}
            ],
            response_format={ "type": "json_object" }
        )
        
        content = response.choices[0].message.content
        import json
        # Cleanup potential markdown code blocks
        if "```json" in content:
            content = content.replace("```json", "").replace("```", "")
        elif "```" in content:
            content = content.replace("```", "")
            
        data = json.loads(content)
        return data.get("matches", [])
        
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
    
    # Reset output file if new run (optional, maybe we want append? Let's overwrite for daily clean run)
    if os.path.exists(args.output):
        os.remove(args.output)

    num_batches = math.ceil(len(all_domains) / args.batch_size)
    
    for i in tqdm(range(0, len(all_domains), args.batch_size), desc="Analyzing Batches"):
        batch = all_domains[i : i + args.batch_size]
        matches = analyze_batch(batch)
        if matches:
            save_matches(matches, args.output)
            total_matches += len(matches)
            
    print(f"Done. Found {total_matches} potential typosquats. Saved to {args.output}")

if __name__ == "__main__":
    main()
