#!/usr/bin/env python3
"""
ai_briefing.py

Generates a daily threat intelligence briefing summary by analyzing:
- Overall stats (counts, top ASNs)
- Newly detected typosquats
- Interesting classifications (Phishing/C2)

Outputs: data/docs/daily_briefing.json
"""

import os
import csv
import json
import argparse
import sys
from datetime import datetime
from collections import Counter
from dotenv import load_dotenv
from litellm import completion

# Load environment variables
load_dotenv()

# Constants
# Primary: GPT-5.2 (High Quality), Fallback: GPT-4o (Reliable)
PRIMARY_MODEL = "gpt-5.2" 
FALLBACK_MODEL = "gpt-4o"
OUTPUT_FILE = "docs/data/daily_briefing.json"
TYPOSQUAT_FILE = "data/ai_typosquats.csv"
CLASSIFICATION_FILE = "data/ai_classifications.csv"
STATS_FILE = "data/dea_domains_probed.csv" # To get total count

SYSTEM_PROMPT = """
You are a Senior Threat Intelligence Analyst. 
Write a concise, executive-level daily briefing based on the provided data.
Tone: Professional, Alert, Action-oriented.
Focus on:
1. Significant volume of incoming domains.
2. Specific high-value targets being impersonated (from typosquats).
3. Any alarming classifications (C2, Phishing campaigns).
4. Top 1-2 acting ASNs if mentioned.

Return JSON format:
{
    "date": "YYYY-MM-DD",
    "headline": "Short punchy headline (e.g. 'Spike in Google Phishing Detected')",
    "summary": "2-3 sentences summarizing the key findings.",
    "key_risks": ["Bullet 1", "Bullet 2", "Bullet 3"],
    "action_items": ["Action 1", "Action 2"]
}
"""

def get_stats():
    stats = {
        "total_domains": 0,
        "typosquats": [],
        "phishing_count": 0,
        "c2_count": 0,
        "top_targets": []
    }
    
    # 1. Total Domains scanned
    if os.path.exists(STATS_FILE):
        with open(STATS_FILE, 'r', encoding='utf-8-sig', errors='replace') as f:
            stats["total_domains"] = sum(1 for row in f) - 1 # minus header

    # 2. Typosquats found
    if os.path.exists(TYPOSQUAT_FILE):
        with open(TYPOSQUAT_FILE, 'r', encoding='utf-8-sig', errors='replace') as f:
            reader = csv.DictReader(f)
            targets = []
            for row in reader:
                stats["typosquats"].append(row.get('domain'))
                targets.append(row.get('target'))
            
            if targets:
                stats["top_targets"] = [t[0] for t in Counter(targets).most_common(3)]

    # 3. Classifications
    if os.path.exists(CLASSIFICATION_FILE):
        with open(CLASSIFICATION_FILE, 'r', encoding='utf-8-sig', errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cat = row.get('category', '').lower()
                if 'phishing' in cat:
                    stats["phishing_count"] += 1
                elif 'c2' in cat:
                    stats["c2_count"] += 1

    return stats

def generate_briefing(stats):
    # Construct the data prompt
    target_str = ", ".join(stats["top_targets"]) if stats["top_targets"] else "None"
    
    # Estimate coverage based on Typosquat/Classify limits
    ai_limit = 1000
    coverage_pct = (ai_limit / stats["total_domains"]) * 100 if stats["total_domains"] > 0 else 0
    
    data_summary = f"""
    Date: {datetime.now().strftime('%Y-%m-%d')}
    Total New Domains Ingested: {stats["total_domains"]}
    Domains Analyzed by AI: ~{ai_limit} ({coverage_pct:.2f}% sample)
    Confirmed Typosquats: {len(stats["typosquats"])}
    Top Impersonated Brands: {target_str}
    Phishing Sites Identified: {stats["phishing_count"]}
    Suspected C2 Panels: {stats["c2_count"]}
    
    IMPORTANT: The AI analysis was performed on a SAMPLE of the total data. 
    Do NOT claim that "no malicious activity was detected" for the entire dataset if the sample was clean.
    State clearly that findings are based on the analyzed sample.
    """
    
    print("Generating briefing with data:")
    print(data_summary)

    # Try Primary AI Model
    try:
        print(f"[*] Attempting generation with {PRIMARY_MODEL}...")
        response = completion(
            model=PRIMARY_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Data for briefing:\n{data_summary}"}
            ],
            response_format={ "type": "json_object" }
        )
    except Exception as e:
        print(f"[!] {PRIMARY_MODEL} failed ({e}). Falling back to {FALLBACK_MODEL}...")
        try:
            response = completion(
                model=FALLBACK_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Data for briefing:\n{data_summary}"}
                ],
                response_format={ "type": "json_object" }
            )
        except Exception as e2:
            print(f"[!] Fallback failed too: {e2}")
            # Return Mock/Fallback dict if both fail
            return {
                "date": datetime.now().strftime('%Y-%m-%d'),
                "headline": "Full Manual Analysis Required",
                "summary": f"AI Generation Failed. Processed {stats['total_domains']} domains.",
                "key_risks": ["AI Unavailable"],
                "action_items": ["Check API Keys", "Check Logs"]
            }

    content = response.choices[0].message.content
    
    # Parse JSON
    import json
    if "```json" in content:
        content = content.replace("```json", "").replace("```", "")
    elif "```" in content:
        content = content.replace("```", "")
        
    briefing = json.loads(content)
    # Ensure date matches today just in case LLM hallucinations
    briefing["date"] = datetime.now().strftime('%Y-%m-%d')
    briefing["model_used"] = response.model # Track which model worked
    
    return briefing
        
    # Fallback/Mock logic is now handled above in the nested try/except
    pass

def save_briefing(briefing):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(briefing, f, indent=2)
    print(f"Briefing saved to {OUTPUT_FILE}")

def main():
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not found in .env. Using fallback/mock if needed, but exiting for now.")
        # Alternatively, fallback to Gemini if OpenAI missing
        if os.getenv("GEMINI_API_KEY"):
            global MODEL
            MODEL = "gemini/gemini-3-flash"
        else:
            sys.exit(1)

    stats = get_stats()
    briefing = generate_briefing(stats)
    save_briefing(briefing)

if __name__ == "__main__":
    main()
