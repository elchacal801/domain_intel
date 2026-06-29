#!/usr/bin/env python3
"""
sync_detection_rules.py

Fetches FLAME detection rules from GitHub Pages and converts applicable
rules into domain_intel triage configuration.

Extracts patterns from Sigma/SPL/SQL rules that match domain_intel's
data model (nameserver patterns, MX patterns, ASN patterns) and outputs
them as config/flame_detection_rules.yaml for analyst review.

This script does NOT auto-apply rules — it generates config that an
analyst reviews before enabling in the triage pipeline.
"""

import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from shared import config as cfg

logger = logging.getLogger(__name__)

# Defaults
_DEFAULT_RULES_URL = "https://elchacal801.github.io/flame-fraud/database/flame_detection_rules.json"
_CACHE_DIR = Path("data/.flame_cache")
_RULES_CACHE = _CACHE_DIR / "flame_detection_rules.json"
_RULES_CACHE_META = _CACHE_DIR / ".rules_meta.json"

OUTPUT_FILE = Path("config/flame_detection_rules.yaml")


# ---------------------------------------------------------------------------
# Fetch & Cache
# ---------------------------------------------------------------------------

def fetch_rules() -> Optional[List[Dict[str, Any]]]:
    """Fetch FLAME detection rules with caching."""
    # Check cache
    if _RULES_CACHE.exists() and _RULES_CACHE_META.exists():
        try:
            with open(_RULES_CACHE_META, "r") as fh:
                meta = json.load(fh)
            ttl = float(cfg.get("flame.cache_ttl_hours", 24)) * 3600
            if (time.time() - meta.get("fetched_at", 0)) < ttl:
                with open(_RULES_CACHE, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                print(f"[*] Rules cache hit ({len(data)} rules)")
                return data
        except (json.JSONDecodeError, OSError, KeyError):
            pass

    # Fetch
    url = cfg.get("flame.detection_rules_url", _DEFAULT_RULES_URL)
    print(f"[*] Fetching FLAME detection rules from {url}...")
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()

        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with open(_RULES_CACHE, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with open(_RULES_CACHE_META, "w") as fh:
            json.dump({"fetched_at": time.time()}, fh)

        print(f"    Fetched {len(data)} rules")
        return data
    except requests.RequestException as exc:
        print(f"[!] Could not fetch FLAME rules: {exc}")

    # Stale fallback
    if _RULES_CACHE.exists():
        try:
            with open(_RULES_CACHE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            pass

    return None


# ---------------------------------------------------------------------------
# Rule Conversion
# ---------------------------------------------------------------------------

def extract_sigma_patterns(rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract domain_intel-relevant patterns from a Sigma rule."""
    content = rule.get("content", "")
    patterns = []

    # Look for domain/nameserver patterns
    ns_patterns = re.findall(
        r"nameserver[_\s]*(?:contains|matches|value)\s*[:\|]\s*['\"]?([^\s'\"]+)",
        content, re.IGNORECASE
    )
    for ns in ns_patterns:
        patterns.append({
            "field": "nameservers",
            "operator": "contains",
            "value": ns,
        })

    # Look for ASN patterns
    asn_patterns = re.findall(
        r"(?:asn|autonomous[-_]system)[_\s]*(?:number)?\s*[=:\|]\s*(\d+)",
        content, re.IGNORECASE
    )
    for asn in asn_patterns:
        patterns.append({
            "field": "asn",
            "operator": "equals",
            "value": f"AS{asn}",
        })

    # Look for IP CIDR patterns
    cidr_patterns = re.findall(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})",
        content
    )
    for cidr in cidr_patterns:
        # Skip private ranges
        if not cidr.startswith(("10.", "172.16.", "192.168.")):
            patterns.append({
                "field": "mx_ip",
                "operator": "cidr",
                "value": cidr,
            })

    # Look for domain name patterns in detection
    domain_patterns = re.findall(
        r"domain[_\s]*(?:contains|matches|value)\s*[:\|]\s*['\"]?([a-z0-9.-]+\.[a-z]{2,})",
        content, re.IGNORECASE
    )
    for d in domain_patterns:
        patterns.append({
            "field": "domain",
            "operator": "contains",
            "value": d,
        })

    return patterns


def extract_sql_patterns(rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract patterns from SQL detection queries."""
    content = rule.get("content", "")
    patterns = []

    # Extract WHERE clause patterns for domain-related fields
    # nameserver LIKE '%pattern%'
    ns_likes = re.findall(
        r"nameserver[s]?\s+(?:LIKE|=)\s+'%?([^'%]+)%?'",
        content, re.IGNORECASE
    )
    for ns in ns_likes:
        patterns.append({
            "field": "nameservers",
            "operator": "contains",
            "value": ns,
        })

    # mx or mail patterns
    mx_likes = re.findall(
        r"(?:mx|mail_server|primary_mx)\s+(?:LIKE|=)\s+'%?([^'%]+)%?'",
        content, re.IGNORECASE
    )
    for mx in mx_likes:
        patterns.append({
            "field": "primary_mx",
            "operator": "contains",
            "value": mx,
        })

    return patterns


def convert_rules(raw_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert FLAME detection rules to domain_intel triage format."""
    triage_rules = []

    for rule in raw_rules:
        rule_type = rule.get("type", "")
        tp_id = rule.get("tp_id", "unknown")
        title = rule.get("title", "")

        patterns = []
        if rule_type in ("sigma", "yaml"):
            patterns = extract_sigma_patterns(rule)
        elif rule_type == "sql":
            patterns = extract_sql_patterns(rule)
        elif rule_type == "spl":
            # SPL uses similar field=value syntax, try Sigma parser
            patterns = extract_sigma_patterns(rule)

        if patterns:
            triage_rules.append({
                "rule_id": f"FLAME-{tp_id}-{len(triage_rules)+1:03d}",
                "source_tp": tp_id,
                "title": title,
                "type": rule_type,
                "enabled": False,  # Analyst must review and enable
                "patterns": patterns,
            })

    return triage_rules


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("[*] FLAME Detection Rule Sync")

    raw_rules = fetch_rules()
    if not raw_rules:
        print("[!] No rules available. Exiting.")
        sys.exit(1)

    print(f"[*] Processing {len(raw_rules)} raw rules...")

    triage_rules = convert_rules(raw_rules)
    print(f"[*] Converted {len(triage_rules)} rules with domain_intel patterns")

    # Write output
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    output = {
        "version": "1.0",
        "source": "FLAME Project (auto-synced)",
        "description": "Detection rules derived from FLAME threat paths. "
                       "Review and set enabled: true for rules to apply in triage.",
        "rules": triage_rules,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(output, f, default_flow_style=False, sort_keys=False,
                  allow_unicode=True)

    print(f"[+] Rules written to {OUTPUT_FILE}")
    if triage_rules:
        print("\n    Rules summary:")
        for r in triage_rules:
            status = "ENABLED" if r["enabled"] else "disabled"
            print(f"    [{status}] {r['rule_id']}: {r['title'][:60]}")
    else:
        print("    No domain_intel-applicable patterns found in FLAME rules.")
        print("    This is normal if FLAME rules target non-domain observables.")

    print("\n[*] Done. Review config/flame_detection_rules.yaml before enabling.")


if __name__ == "__main__":
    main()
