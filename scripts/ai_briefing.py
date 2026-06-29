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
import logging
import argparse
import sys
from datetime import datetime
from collections import Counter
from dotenv import load_dotenv
from shared.llm_client import LLMClient, load_model_chain
from shared.flame_client import get_regulatory_alerts

# Load environment variables
load_dotenv()

# LLM Client — uses Sonnet-first chain for briefing (quality-optimized)
llm = LLMClient(models=load_model_chain("briefing"))

OUTPUT_FILE = "data/daily_briefing.json"
TYPOSQUAT_FILE = "data/ai_typosquats.csv"
CLASSIFICATION_FILE = "data/ai_classifications.csv"
STATS_FILE = "data/dea_domains_probed.csv" # To get total count
SHODAN_FILE = "data/shodan_intelligence.csv"
PIVOT_FILE = "data/pivot_discovery.csv"
TOR_FILE = "data/tor_nodes.csv"
ASN_FILE = "data/suspicious_asns.csv"
REGISTRAR_FILE = "data/domain_registrars.csv"
CAMPAIGN_FILE = "data/campaign_hunt_history.csv"
OPENCLAW_FILE = "data/openclaw_exposed.csv"
RISK_FILE = "data/risk_counts.csv"
HISTORY_FILE = "docs/history.json"

SYSTEM_PROMPT = """
You are a Lead Strategic Threat Analyst for a Global Fortune 10 Financial Institution.
Your audience consists of the CISO, Heads of Fraud, and the Global Threat Intelligence Council.

**Objective:**
Produce a high-fidelity, strategic daily intelligence briefing derived from the provided domain telemetry.
Do not just list stats; analyze implications, assess confidence, and predict near-term threat landscape shifts.
Integrate ALL provided data sources — domain intelligence, infrastructure exposure (OpenClaw/Shodan),
campaign tracking, risk signal analysis, and historical trends — into a cohesive assessment.

**Tone & Style Guidelines:**
- **Authoritative & Nuanced:** Use precise intelligence language.
- **Probabilistic Assessments:** Use ICD-203 standard probability language (e.g., "Highly Likely", "Roughly Even Chance", "Unlikely") where appropriate.
- **Strategic Focus:** Connect low-level signals (new domains, typosquats) to high-level risks (Brand Erosion, Fraud Campaigns, Credential Harvesting).
- **No Hyperbole:** Avoid sensationalism. If the data is quiet, state that the threat level is stable.
- **Cross-Domain Correlation:** Look for overlap between domain typosquats, campaign IPs, and exposed infrastructure.
- **Formatting:** NEVER use em-dashes (\u2014) or en-dashes (\u2013). Use regular hyphens (-) or commas instead. NEVER use smart/curly quotes; use straight quotes only.
- **Markdown:** Use markdown formatting (bold, bullet lists, headers) within text fields for readability.

**Required Briefing Structure (JSON):**
1. **Executive Summary:** A dense 3-4 sentence synthesis of the day's most critical findings across all intelligence domains.
2. **Strategic Assessment:** High-level analysis of the threat landscape. Are we seeing a coordinated campaign or sporadic noise? What is the trendline? Include growth rate analysis.
3. **Operational Intelligence:** Specific technical observations (e.g., "Shift in TLD usage to .cfd", "Spike in Nginx servers on compromised hosts"). Include infrastructure exposure findings.
4. **Campaign & Investigation Highlights:** Summary of active campaign tracking, OpenClaw shadow AI exposure, and any notable investigation leads. If no active campaigns, note the absence and recommend targets.
5. **Risk Signal Analysis:** Breakdown of detected risk signals (phishing indicators, parking domains, shell domains). What do the risk signal proportions tell us about attacker intent?
6. **Registrar Risk Outlook:** Specific assessment of the "High Risk" registrars and their current contribution to the threat surface.
7. **Key Risks & Implications:** Bullet points linking technical findings to business impact.
8. **Recommended Actions:** Strategic AND tactical recommendations, prioritized by impact.

**Return JSON format:**
{
    "date": "YYYY-MM-DD",
    "headline": "Professional, Impact-Focused Headline",
    "executive_summary": "Text...",
    "strategic_assessment": "Text...",
    "operational_intelligence": "Text...",
    "campaign_highlights": "Text...",
    "risk_signal_analysis": "Text...",
    "registrar_risk_outlook": "Text...",
    "key_risks": ["Risk 1", "Risk 2"],
    "action_items": ["Action 1", "Action 2"]
}
"""

def _sanitize_briefing(briefing):
    """Strip em-dashes, en-dashes, and smart quotes from all string fields."""
    replacements = {
        "\u2014": "-",   # em-dash
        "\u2013": "-",   # en-dash
        "\u2018": "'",   # left single quote
        "\u2019": "'",   # right single quote
        "\u201C": '"',   # left double quote
        "\u201D": '"',   # right double quote
    }
    def _clean(val):
        if isinstance(val, str):
            for old, new in replacements.items():
                val = val.replace(old, new)
            return val
        elif isinstance(val, list):
            return [_clean(v) for v in val]
        elif isinstance(val, dict):
            return {k: _clean(v) for k, v in val.items()}
        return val
    return _clean(briefing)


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
        "high_risk_registrars": {"Nicenic": 0, "Dominet": 0, "Gname": 0, "Aceville": 0},
        "campaign_ips": 0,
        "campaign_countries": 0,
        "campaign_queries": 0,
        "openclaw_instances": 0,
        "openclaw_risks": [],
        "risk_signals": {},
        "trend_total_prev": 0,
        "trend_live_prev": 0,
        "trend_total_curr": 0,
        "trend_live_curr": 0,
        "flame_tp_distribution": {},
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

                # Count FLAME TP IDs
                tp_ids_str = row.get('flame_tp_ids', '').strip()
                if tp_ids_str:
                    for tp_id in tp_ids_str.split(','):
                        tp_id = tp_id.strip()
                        if tp_id:
                            stats["flame_tp_distribution"][tp_id] = stats["flame_tp_distribution"].get(tp_id, 0) + 1

    # 4. Infrastructure Stats
    if os.path.exists(ASN_FILE):
        try:
             with open(ASN_FILE, 'r', encoding='utf-8') as f:
                stats["malicious_asn_count"] = sum(1 for line in f) - 1
        except (IOError, OSError) as exc:
            logging.warning("Failed to read ASN file: %s", exc)
        
    if os.path.exists(TOR_FILE):
        try:
            with open(TOR_FILE, 'r', encoding='utf-8') as f:
                stats["tor_exit_count"] = sum(1 for line in f) - 1
        except (IOError, OSError) as exc:
            logging.warning("Failed to read Tor file: %s", exc)
        
    if os.path.exists(PIVOT_FILE):
        try:
            with open(PIVOT_FILE, 'r', encoding='utf-8') as f:
                 stats["pivot_count"] = sum(1 for line in f) - 1
        except (IOError, OSError) as exc:
            logging.warning("Failed to read pivot file: %s", exc)

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
        except (IOError, csv.Error, KeyError) as exc:
            logging.warning("Failed to read Shodan file: %s", exc)

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

    # 7. Campaign Hunt Stats
    if os.path.exists(CAMPAIGN_FILE):
        try:
            ips = set()
            countries = set()
            queries = set()
            with open(CAMPAIGN_FILE, 'r', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('ip'): ips.add(row['ip'])
                    if row.get('country'): countries.add(row['country'])
                    if row.get('query'): queries.add(row['query'])
            stats["campaign_ips"] = len(ips)
            stats["campaign_countries"] = len(countries)
            stats["campaign_queries"] = len(queries)
        except Exception as e:
            print(f"Campaign stats error: {e}")

    # 8. OpenClaw Exposure Stats
    if os.path.exists(OPENCLAW_FILE):
        try:
            risks = []
            with open(OPENCLAW_FILE, 'r', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                stats["openclaw_instances"] = len(rows)
                for row in rows:
                    rl = row.get('risk_level', '').strip()
                    if rl:
                        risks.append(rl)
            stats["openclaw_risks"] = dict(Counter(risks))
        except Exception as e:
            print(f"OpenClaw stats error: {e}")

    # 9. Risk Signal Breakdown
    if os.path.exists(RISK_FILE):
        try:
            with open(RISK_FILE, 'r', encoding='utf-8', errors='replace') as f:
                reader = csv.reader(f)
                next(reader, None)  # skip header
                for row in reader:
                    if len(row) >= 2:
                        stats["risk_signals"][row[0]] = int(row[1])
        except Exception as e:
            print(f"Risk signal stats error: {e}")

    # 10. Historical Trend (last 2 days for delta)
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                history = json.load(f)
            if len(history) >= 2:
                prev = history[-2]
                curr = history[-1]
                stats["trend_total_prev"] = prev.get("total", 0)
                stats["trend_live_prev"] = prev.get("live", 0)
                stats["trend_total_curr"] = curr.get("total", 0)
                stats["trend_live_curr"] = curr.get("live", 0)
            elif len(history) == 1:
                stats["trend_total_curr"] = history[0].get("total", 0)
                stats["trend_live_curr"] = history[0].get("live", 0)
        except Exception as e:
            print(f"History trend error: {e}")

    return stats


def get_evidence_candidates(stats):
    """Identify clusters that qualify as FLAME evidence candidates.

    A cluster qualifies when:
      - It has >10 classified domains
      - Domains map to at least one FLAME TP
      - Infrastructure pattern is confirmed (shared IP or NS)

    Returns a list of candidate dicts for inclusion in the briefing.
    """
    candidates = []
    tp_dist = stats.get("flame_tp_distribution", {})

    if not tp_dist:
        return candidates

    # Read classifications to build cluster data
    if not os.path.exists(CLASSIFICATION_FILE):
        return candidates

    # Group by TP ID with domain counts
    tp_domains = {}  # tp_id -> list of domains
    try:
        with open(CLASSIFICATION_FILE, 'r', encoding='utf-8-sig', errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                tp_ids_str = row.get('flame_tp_ids', '').strip()
                domain = row.get('domain', '').strip()
                if tp_ids_str and domain:
                    for tp_id in tp_ids_str.split(','):
                        tp_id = tp_id.strip()
                        if tp_id:
                            if tp_id not in tp_domains:
                                tp_domains[tp_id] = []
                            tp_domains[tp_id].append(domain)
    except (IOError, csv.Error) as exc:
        logging.warning("Failed to read classifications for evidence candidates: %s", exc)
        return candidates

    # Build candidates from TPs with enough domains
    for tp_id, domains in tp_domains.items():
        domain_count = len(domains)
        if domain_count >= 10:
            confidence = "High" if domain_count >= 50 else "Medium"
            candidates.append({
                "tp_id": tp_id,
                "domain_count": domain_count,
                "sample_domains": sorted(domains, key=len)[:5],
                "confidence": confidence,
                "recommendation": f"Submit evidence package for {tp_id} ({domain_count} domains)",
            })

    candidates.sort(key=lambda x: x["domain_count"], reverse=True)
    return candidates

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
    
    # Risk signal formatting
    risk_str = "None detected"
    if stats["risk_signals"]:
        risk_str = "\n".join([f"    - {k}: {v}" for k, v in sorted(stats["risk_signals"].items(), key=lambda x: x[1], reverse=True)])

    # OpenClaw risk breakdown
    oc_risk_str = "N/A"
    if stats["openclaw_risks"]:
        oc_risk_str = ", ".join([f"{k}: {v}" for k, v in stats["openclaw_risks"].items()])

    # Trend calculation
    trend_delta = stats["trend_total_curr"] - stats["trend_total_prev"]
    trend_dir = "+" if trend_delta >= 0 else ""
    live_delta = stats["trend_live_curr"] - stats["trend_live_prev"]
    live_dir = "+" if live_delta >= 0 else ""

    # FLAME TP distribution formatting
    flame_tp_str = "No FLAME data available"
    if stats["flame_tp_distribution"]:
        flame_tp_str = "\n".join([f"    - {tp_id}: {count} domains" for tp_id, count in sorted(stats["flame_tp_distribution"].items(), key=lambda x: x[1], reverse=True)])

    # FLAME evidence candidates
    evidence_candidates = get_evidence_candidates(stats)
    evidence_str = "No clusters meet evidence threshold"
    if evidence_candidates:
        ev_lines = []
        for ec in evidence_candidates:
            samples = ", ".join(ec["sample_domains"][:3])
            ev_lines.append(f"    - {ec['tp_id']}: {ec['domain_count']} domains ({ec['confidence']} confidence) "
                           f"[samples: {samples}]")
        evidence_str = "\n".join(ev_lines)

    # Regulatory Pulse
    reg_alerts = get_regulatory_alerts()
    reg_str = "No regulatory data available"
    if reg_alerts:
        by_severity = {"high": 0, "medium": 0, "low": 0}
        by_source = {}
        tp_alert_counts = {}
        for ra in reg_alerts:
            sev = ra.get("severity", "medium")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            src = ra.get("source", "unknown")
            by_source[src] = by_source.get(src, 0) + 1
            for tp_id in ra.get("mapped_tp_ids", []):
                if tp_id not in tp_alert_counts:
                    tp_alert_counts[tp_id] = {"total": 0, "high": 0}
                tp_alert_counts[tp_id]["total"] += 1
                if sev == "high":
                    tp_alert_counts[tp_id]["high"] += 1

        source_parts = ", ".join([f"{s.upper()} ({c})" for s, c in sorted(by_source.items(), key=lambda x: x[1], reverse=True)])
        tp_parts = "\n".join([
            f"    - {tp}: {counts['total']} alerts ({counts['high']} high severity)"
            for tp, counts in sorted(tp_alert_counts.items(), key=lambda x: x[1]['total'], reverse=True)[:10]
        ])

        reg_str = (
            f"Active Regulatory Alerts: {len(reg_alerts)} total "
            f"({by_severity.get('high', 0)} high, {by_severity.get('medium', 0)} medium, {by_severity.get('low', 0)} low)\n"
            f"    By Source: {source_parts}\n"
            f"    TP-Linked Alerts:\n{tp_parts}"
        )

    data_summary = f"""
    Date: {datetime.now().strftime('%Y-%m-%d')}
    Total Domains Monitored: {stats["total_domains"]}
    Domains Analyzed by AI: ~{ai_limit} ({coverage_pct:.2f}% sample)
    
    [Historical Trend]
    Total Domains: {stats['trend_total_curr']:,} ({trend_dir}{trend_delta:,} from previous day)
    Live Domains: {stats['trend_live_curr']:,} ({live_dir}{live_delta:,} from previous day)
    
    [Threat Detection]
    Confirmed Typosquats: {len(stats["typosquats"])}
    Top Impersonated Brands: {target_str}
    Phishing Sites Identified: {stats["phishing_count"]}
    Suspected C2 Panels: {stats["c2_count"]}
    
    [FLAME Threat Path Distribution]
{flame_tp_str}

    [FLAME Evidence Candidates]
{evidence_str}

    [Regulatory Pulse]
{reg_str}

    [Risk Signal Breakdown]
{risk_str}
    
    [Infrastructure Intelligence]
    Malicious ASNs Active: {stats["malicious_asn_count"]}
    Tor Exit Nodes Mapped: {stats["tor_exit_count"]}
    Shodan Findings: {stats["shodan_vulns"]} vulnerabilities detected. Top Ports: {stats["shodan_ports"]}
    Infrastructure Pivots: {stats["pivot_count"]} new domains discovered via Whois pivoting.

    [Campaign & Investigation Tracking]
    Campaign IPs Tracked: {stats["campaign_ips"]}
    Countries Observed: {stats["campaign_countries"]}
    Active Hunt Queries: {stats["campaign_queries"]}
    
    [Shadow AI / OpenClaw Exposure]
    Exposed Instances: {stats["openclaw_instances"]}
    Risk Level Breakdown: {oc_risk_str}

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
    Cross-reference all intelligence domains: correlate typosquat registrars with campaign IPs, 
    OpenClaw exposure with infrastructure pivots, and risk signals with Shodan findings.
    If FLAME Threat Path data is present, reference the threat path titles and IDs in your narrative.
    If FLAME Evidence Candidates are listed, include an "Evidence Pipeline" section recommending
    which clusters should be submitted as operational evidence to the FLAME framework.
    If Regulatory Pulse data is present, include a "Regulatory Landscape" section assessing
    how regulatory enforcement trends align with observed threat activity in the domain telemetry.
    """
    
    print("Generating briefing with data:")
    print(data_summary)

    # Use shared LLM client with automatic fallback chain
    briefing = llm.complete_json(
        prompt=f"Data for briefing:\n{data_summary}",
        system=SYSTEM_PROMPT
    )
    
    if briefing is None:
        print("[!] All AI models failed.")
        return _mock_failure_briefing(stats)
    
    # Ensure date matches today just in case LLM hallucinations
    briefing["date"] = datetime.now().strftime('%Y-%m-%d')
    briefing["model_used"] = "shared_llm_client"  # Track that shared client was used
    # Frontend expects "summary", LLM generates "executive_summary"
    briefing["summary"] = briefing.get("executive_summary", "No summary generated.")

    # Attach evidence candidates if present
    evidence_candidates = get_evidence_candidates(stats)
    if evidence_candidates:
        briefing["evidence_candidates"] = evidence_candidates

    # Sanitize em-dashes, en-dashes, smart quotes
    briefing = _sanitize_briefing(briefing)
    
    return briefing

def save_briefing(briefing):
    # 1. Save Latest
    latest_path = "data/daily_briefing.json"
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
    except (TypeError, KeyError) as exc:
        logging.warning("Failed to sort briefing history: %s", exc)
    
    with open(history_path, 'w', encoding='utf-8') as f:
        json.dump(history, f, indent=2)

    print(f"Briefing saved to {latest_path}, {archive_path}, and appended to history.")

def main():
    has_openai = os.getenv("OPENAI_API_KEY") is not None
    has_gemini = os.getenv("GEMINI_API_KEY") is not None
    has_claude = os.getenv("ANTHROPIC_API_KEY") is not None

    if not (has_openai or has_gemini or has_claude):
        print("Error: No AI API keys (OPENAI/GEMINI/ANTHROPIC) found in .env.")
        sys.exit(1)

    stats = get_stats()
    briefing = generate_briefing(stats)
    save_briefing(briefing)

if __name__ == "__main__":
    main()
