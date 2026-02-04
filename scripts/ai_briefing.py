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
GEMINI_MODEL = "gemini/gemini-3-pro"
OUTPUT_FILE = "docs/data/daily_briefing.json"
TYPOSQUAT_FILE = "data/ai_typosquats.csv"
CLASSIFICATION_FILE = "data/ai_classifications.csv"
STATS_FILE = "data/dea_domains_probed.csv" # To get total count
SHODAN_FILE = "data/shodan_intelligence.csv"
PIVOT_FILE = "data/pivot_discovery.csv"
TOR_FILE = "data/tor_nodes.csv"
ASN_FILE = "data/suspicious_asns.csv"
REGISTRAR_FILE = "data/domain_registrars.csv"

SYSTEM_PROMPT = """
You are a Lead Strategic Threat Analyst for a Global Fortune 10 Financial Institution.
Your audience consists of the CISO, Heads of Fraud, and the Global Threat Intelligence Council.

**Objective:**
Produce a high-fidelity, strategic daily intelligence briefing derived from the provided domain telemetry.
Do not just list stats; analyze implications, assess confidence, and predict near-term threat landscape shifts.

**Tone & Style Guidelines:**
- **Authoritative & Nuanced:** Use precise intelligence language.
- **Probabilistic Assessments:** Use ICD-203 standard probability language (e.g., "Highly Likely", "Roughly Even Chance", "Unlikely") where appropriate.
- **Strategic Focus:** Connect low-level signals (new domains, typosquats) to high-level risks (Brand Erosion, Fraud Campaigns, Credential Harvesting).
- **No Hyperbole:** Avoid sensationalism. If the data is quiet, state that the threat level is stable.

**Required Briefing Structure (JSON):**
1. **Executive Summary:** A dense 3-4 sentence synthesis of the day's most critical findings.
2. **Strategic Assessment:** High-level analysis of the threat landscape. Are we seeing a coordinated campaign or sporadic noise? What is the trendline?
3. **Operational Intelligence:** specific technical observations (e.g., "Shift in TLD usage to .cfd", "Spike in Nginx servers on compromised hosts").
4. **Registrar Risk Outlook:** Specific assessment of the "High Risk" registrars (Nicenic, etc.) and their current contribution to the threat surface.
5. **Key Risks & Implications:** Bullet points linking technical findings to business impact.
6. **Recommended Actions:** Strategic and tactical recommendations.

**Return JSON format:**
{
    "date": "YYYY-MM-DD",
    "headline": "Professional, Impact-Focused Headline (e.g. 'Coordinated Infrastructure Spike Detected in .CFD Namespace')",
    "executive_summary": "Text...",
    "strategic_assessment": "Text...",
    "operational_intelligence": "Text...",
    "registrar_risk_outlook": "Text...",
    "key_risks": ["Risk 1", "Risk 2"],
    "action_items": ["Action 1", "Action 2"]
}
"""

def get_stats():
    stats = {
        "total_domains": 0,
        "typosquats": [],
        "phishing_count": 0,
        "c2_count": 0,
        "top_targets": [],
        "malicious_asn_count": 0,
        "tor_exit_count": 0,
        "pivot_count": 0,
        "shodan_ports": "None",
        "shodan_vulns": 0,
        "top_typosquat_registrars": "None",
        "high_risk_registrars": {"Nicenic": 0, "Dominet": 0, "Gname": 0, "Aceville": 0}
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

    # 4. Infrastructure Stats
    if os.path.exists(ASN_FILE):
        try:
             with open(ASN_FILE, 'r', encoding='utf-8') as f:
                stats["malicious_asn_count"] = sum(1 for line in f) - 1
        except: pass
        
    if os.path.exists(TOR_FILE):
        try:
            with open(TOR_FILE, 'r', encoding='utf-8') as f:
                stats["tor_exit_count"] = sum(1 for line in f) - 1
        except: pass
        
    if os.path.exists(PIVOT_FILE):
        try:
            with open(PIVOT_FILE, 'r', encoding='utf-8') as f:
                 stats["pivot_count"] = sum(1 for line in f) - 1
        except: pass

    # 5. Shodan Stats
    if os.path.exists(SHODAN_FILE):
        try:
            ports = []
            vulns = 0
            with open(SHODAN_FILE, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    p_str = row.get('ports', '')
                    if p_str:
                        ports.extend(p_str.split(';'))
                    if row.get('vulns'):
                        vulns += len(row.get('vulns').split(';'))
            
            top_ports = [p[0] for p in Counter(ports).most_common(3)]
            stats["shodan_ports"] = ", ".join(top_ports)
            stats["shodan_vulns"] = vulns
        except: pass

    # 6. Registrar Stats (New)
    if os.path.exists(REGISTRAR_FILE):
        try:
            # High Risk Keywords (Case Insensitive)
            watchlist = {
                "Nicenic": ["nicenic", "3765"],
                "Dominet": ["dominet", "3775"],
                "Gname": ["gname", "1923"],
                "Aceville": ["aceville", "3858"]
            }
            
            domain_reg_map = {}
            with open(REGISTRAR_FILE, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    reg = row.get('registrar', '').strip()
                    dom = row.get('domain', '').strip()
                    if dom:
                        domain_reg_map[dom] = reg
                    
                    # Watchlist Counting
                    reg_lower = reg.lower()
                    for name, keys in watchlist.items():
                        if any(k in reg_lower for k in keys):
                            stats["high_risk_registrars"][name] += 1

            # Map confirmed typosquats to registrars
            typo_regs = []
            for t_dom in stats["typosquats"]:
                r = domain_reg_map.get(t_dom, "Unknown")
                typo_regs.append(r)
            
            if typo_regs:
                top = Counter(typo_regs).most_common(3)
                stats["top_typosquat_registrars"] = ", ".join([f"{t[0]} ({t[1]})" for t in top])
                
        except Exception as e:
            print(f"Registrar stats error: {e}")

    return stats

def _mock_failure_briefing(stats):
    return {
        "date": datetime.now().strftime('%Y-%m-%d'),
        "headline": "Full Manual Analysis Required",
        "executive_summary": f"AI Generation Failed after exhausting all models. Processed {stats['total_domains']} domains.",
        "strategic_assessment": "Automated analysis unavailable. Review stats manually.",
        "operational_intelligence": "N/A",
        "registrar_risk_outlook": "N/A",
        "key_risks": ["AI Unavailable", "Quota Exceeded"],
        "action_items": ["Check API Keys", "Check Billing"]
    }

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
    
    [Threat Detection]
    Confirmed Typosquats: {len(stats["typosquats"])}
    Top Impersonated Brands: {target_str}
    Phishing Sites Identified: {stats["phishing_count"]}
    Suspected C2 Panels: {stats["c2_count"]}
    
    [Infrastructure Intelligence]
    Malicious ASNs Active: {stats["malicious_asn_count"]}
    Tor Exit Nodes Mapped: {stats["tor_exit_count"]}
    Shodan Findings: {stats["shodan_vulns"]} vulnerabilities detected. Top Ports: {stats["shodan_ports"]}
    Infrastructure Pivots: {stats["pivot_count"]} new domains discovered via Whois pivoting.

    [Registrar Concentration Risk]
    Top Registrars for Confirmed Typosquats: {stats["top_typosquat_registrars"]}
    
    *High Risk Registrar Presence (Watchlist)*:
    - Nicenic: {stats["high_risk_registrars"].get("Nicenic", 0)} domains
    - Dominet: {stats["high_risk_registrars"].get("Dominet", 0)} domains
    - Gname: {stats["high_risk_registrars"].get("Gname", 0)} domains
    - Aceville: {stats["high_risk_registrars"].get("Aceville", 0)} domains
    
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
            print(f"[!] Fallback (GPT-4o) failed: {e2}")
            
            # 3. Try Gemini Fallback
            if os.getenv("GEMINI_API_KEY"):
                try:
                    print(f"[*] Attempting generation with {GEMINI_MODEL}...")
                    response = completion(
                        model=GEMINI_MODEL,
                        messages=[
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": f"Data for briefing:\n{data_summary}"}
                        ],
                        response_format={ "type": "json_object" }
                    )
                except Exception as e3:
                    print(f"[!] Gemini fallback failed: {e3}")
                    return _mock_failure_briefing(stats)
            else:
                return _mock_failure_briefing(stats)

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
    # 1. Save Latest
    latest_path = "docs/data/daily_briefing.json"
    os.makedirs(os.path.dirname(latest_path), exist_ok=True)
    with open(latest_path, 'w', encoding='utf-8') as f:
        json.dump(briefing, f, indent=2)
        
    # 2. Save Historic Archive (Individual File)
    date_str = briefing.get("date", datetime.now().strftime('%Y-%m-%d'))
    archive_dir = "docs/data/briefings"
    os.makedirs(archive_dir, exist_ok=True)
    archive_path = os.path.join(archive_dir, f"briefing_{date_str}.json")
    with open(archive_path, 'w', encoding='utf-8') as f:
        json.dump(briefing, f, indent=2)

    # 3. Update History Aggregate (For Frontend Trends)
    history_path = "docs/data/briefing_history.json"
    history = []
    if os.path.exists(history_path):
        try:
            with open(history_path, 'r', encoding='utf-8') as f:
                history = json.load(f)
        except Exception as e:
            print(f"Warning loading history: {e}")
    
    # Deduplicate by date (remove existing entry for today if re-running)
    history = [b for b in history if b.get("date") != date_str]
    history.append(briefing)
    
    # Sort descending by date
    try:
        history.sort(key=lambda x: x.get("date", ""), reverse=True)
    except: pass
    
    with open(history_path, 'w', encoding='utf-8') as f:
        json.dump(history, f, indent=2)

    print(f"Briefing saved to {latest_path}, {archive_path}, and appended to history.")

def main():
    has_openai = os.getenv("OPENAI_API_KEY") is not None
    has_gemini = os.getenv("GEMINI_API_KEY") is not None
    
    if not has_openai and not has_gemini:
        print("Error: No AI API keys (OPENAI_API_KEY or GEMINI_API_KEY) found in .env.")
        sys.exit(1)

    stats = get_stats()
    briefing = generate_briefing(stats)
    save_briefing(briefing)

if __name__ == "__main__":
    main()
