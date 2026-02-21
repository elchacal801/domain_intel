#!/usr/bin/env python3
"""
export_stix.py

Converts enriched CSV data into STIX 2.1 JSON bundles using the stix2 library.

Produces two bundles:
  1. data/domain_intel_bundle.json      — standalone indicators (backward compat)
  2. data/domain_intel_flame_bundle.json — enriched with FLAME attack-patterns
     and indicator-to-attack-pattern relationships

Supports:
  - Enriched Domains (dea_domains_enriched.csv)
  - Suspicious ASNs (suspicious_asns.csv)
  - VPN/VPS ASNs (vpn_asns.csv)
  - Tor ASNs (tor_asns.csv)
  - Tor Exit Nodes (tor_nodes.csv)
  - Shodan Intelligence (shodan_intelligence.csv)
  - FLAME threat path linkage via ai_classifications.csv
"""

import argparse
import csv
import json
import logging
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    import stix2
except ImportError:
    print("[!] stix2 required: pip install stix2>=3.0.0")
    sys.exit(1)

import requests

# Add shared module path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from shared import config as cfg

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # NAMESPACE_DNS

IDENTITY_UUID = uuid.uuid5(NAMESPACE, "domain_intel_github_action")
IDENTITY_ID = f"identity--{IDENTITY_UUID}"

TLP_CLEAR = stix2.TLP_WHITE  # stix2 uses TLP_WHITE for TLP:CLEAR
TLP_CLEAR_ID = TLP_CLEAR.id

# FLAME defaults
_DEFAULT_STIX_URL = "https://elchacal801.github.io/flame-fraud/database/flame_stix_bundle.json"
_CACHE_DIR = Path("data/.flame_cache")
_STIX_CACHE = _CACHE_DIR / "flame_stix_bundle.json"
_STIX_CACHE_META = _CACHE_DIR / ".stix_meta.json"

CLASSIFICATION_FILE = "data/ai_classifications.csv"


# ---------------------------------------------------------------------------
# Deterministic IDs
# ---------------------------------------------------------------------------

def det_id(stix_type: str, seed: str) -> str:
    """Generate a deterministic STIX ID."""
    return f"{stix_type}--{uuid.uuid5(NAMESPACE, seed)}"


# ---------------------------------------------------------------------------
# STIX Object Builders
# ---------------------------------------------------------------------------

def build_identity() -> stix2.Identity:
    """Build the domain_intel identity."""
    return stix2.Identity(
        id=IDENTITY_ID,
        name="Domain Intel Bot",
        identity_class="system",
        description="Automated Domain Intelligence GitHub Action/Bot",
        object_marking_refs=[TLP_CLEAR_ID],
        external_references=[{
            "source_name": "Domain Intel Repo",
            "description": "Automated threat intelligence pipeline",
            "url": "https://github.com/elchacal801/domain_intel",
        }],
        allow_custom=True,
    )


def build_indicator(value: str, indicator_type: str, labels: List[str],
                    name: str, description: str = "",
                    confidence: int = 50) -> Optional[stix2.Indicator]:
    """Build a STIX indicator from a value."""
    if indicator_type == "domain-name":
        pattern = f"[domain-name:value = '{value}']"
    elif indicator_type == "autonomous-system":
        clean_asn = value.upper().replace("AS", "")
        if not clean_asn.isdigit():
            return None
        pattern = f"[autonomous-system:number = {clean_asn}]"
    elif indicator_type == "ipv4-addr":
        pattern = f"[ipv4-addr:value = '{value}']"
    else:
        return None

    ind_id = det_id("indicator", pattern)

    try:
        return stix2.Indicator(
            id=ind_id,
            created_by_ref=IDENTITY_ID,
            name=name,
            description=description or name,
            pattern=pattern,
            pattern_type="stix",
            valid_from=stix2.utils.get_timestamp(),
            labels=labels,
            indicator_types=["malicious-activity" if "malicious" in str(labels)
                             else "anomalous-activity"],
            confidence=confidence,
            object_marking_refs=[TLP_CLEAR_ID],
            external_references=[{
                "source_name": "Domain Intel Repo",
                "description": "Automated threat intelligence pipeline",
                "url": "https://github.com/elchacal801/domain_intel",
            }],
            allow_custom=True,
        )
    except (stix2.exceptions.InvalidValueError, Exception) as exc:
        # stix2-patterns ANTLR grammar can reject valid patterns
        # (e.g. large AS numbers). Log and skip gracefully.
        logger.debug("Skipping indicator %s: %s", value, exc)
        return None


def build_relationship(source_ref: str, target_ref: str,
                       rel_type: str = "indicates") -> stix2.Relationship:
    """Build a STIX relationship."""
    seed = f"rel-{source_ref}-{rel_type}-{target_ref}"
    return stix2.Relationship(
        id=det_id("relationship", seed),
        relationship_type=rel_type,
        source_ref=source_ref,
        target_ref=target_ref,
        created_by_ref=IDENTITY_ID,
        object_marking_refs=[TLP_CLEAR_ID],
        allow_custom=True,
    )


# ---------------------------------------------------------------------------
# CSV Processing
# ---------------------------------------------------------------------------

def process_domains(filepath: str, labels: List[str],
                    confidence: int = 60) -> List[stix2.Indicator]:
    """Process domain CSV into indicators."""
    indicators = []
    if not os.path.exists(filepath):
        print(f"[!] Skipping {filepath} (Not Found)")
        return indicators

    print(f"[*] Processing domains from {filepath}...")
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            val = row.get("domain", "").strip()
            if not val:
                continue
            ind = build_indicator(val, "domain-name",
                                  labels + ["suspicious-domain"],
                                  f"Suspicious Domain: {val}",
                                  confidence=confidence)
            if ind:
                indicators.append(ind)

    print(f"    - {len(indicators)} domain indicators")
    return indicators


def process_asns(filepath: str, labels: List[str],
                 confidence: int = 50) -> List[stix2.Indicator]:
    """Process ASN CSV into indicators."""
    indicators = []
    if not os.path.exists(filepath):
        print(f"[!] Skipping {filepath} (Not Found)")
        return indicators

    print(f"[*] Processing ASNs from {filepath}...")
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            val = row.get("ASN", row.get("asn", "")).strip()
            name = row.get("Name", row.get("asn_name", "Unknown"))
            if not val:
                continue
            desc = f"Suspicious ASN: {val} ({name})"
            ind = build_indicator(val, "autonomous-system", labels, desc, desc,
                                  confidence=confidence)
            if ind:
                indicators.append(ind)

    print(f"    - {len(indicators)} ASN indicators")
    return indicators


def process_ips(filepath: str, labels: List[str],
                confidence: int = 90) -> List[stix2.Indicator]:
    """Process IP CSV into indicators."""
    indicators = []
    if not os.path.exists(filepath):
        print(f"[!] Skipping {filepath} (Not Found)")
        return indicators

    print(f"[*] Processing IPs from {filepath}...")
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            val = row.get("IP", row.get("ip", "")).strip()
            if not val:
                continue
            desc = f"Suspicious IP: {val}"
            ind = build_indicator(val, "ipv4-addr", labels, desc, desc,
                                  confidence=confidence)
            if ind:
                indicators.append(ind)

    print(f"    - {len(indicators)} IP indicators")
    return indicators


def process_shodan(filepath: str) -> List[stix2.Indicator]:
    """Process Shodan intelligence CSV."""
    indicators = []
    if not os.path.exists(filepath):
        print(f"[!] Skipping Shodan {filepath} (Not Found)")
        return indicators

    print(f"[*] Processing Shodan from {filepath}...")
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("ip") or row.get("shodan_ip") or row.get("mx_ip")
            vulns = row.get("vulns", "")
            tags = row.get("tags", "")
            if not ip or not (vulns or "compromised" in tags):
                continue

            labels = ["vulnerable-host"]
            if "compromised" in tags:
                labels.append("compromised")

            desc_parts = []
            if tags:
                desc_parts.append(f"Tags: {tags}")
            if vulns:
                desc_parts.append(f"Vulns: {vulns}")
            desc = f"Shodan Host: {ip} | " + ", ".join(desc_parts)

            ind = build_indicator(ip, "ipv4-addr", labels,
                                  f"Vulnerable Host: {ip}", desc,
                                  confidence=85)
            if ind:
                indicators.append(ind)

    print(f"    - {len(indicators)} Shodan indicators")
    return indicators


# ---------------------------------------------------------------------------
# FLAME Integration
# ---------------------------------------------------------------------------

def load_flame_tp_mapping() -> Dict[str, List[str]]:
    """Load domain -> FLAME TP ID mappings from ai_classifications.csv."""
    mapping: Dict[str, List[str]] = {}
    if not os.path.exists(CLASSIFICATION_FILE):
        return mapping
    try:
        with open(CLASSIFICATION_FILE, "r", encoding="utf-8-sig",
                  errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                tp_ids_str = row.get("flame_tp_ids", "").strip()
                if tp_ids_str:
                    domain = row.get("domain", "").strip().lower()
                    tp_ids = [t.strip() for t in tp_ids_str.split(",")
                              if t.strip()]
                    if domain and tp_ids:
                        mapping[domain] = tp_ids
    except (IOError, csv.Error) as exc:
        logger.warning("Could not load FLAME TP IDs: %s", exc)
    return mapping


def fetch_flame_stix_bundle() -> Optional[Dict[str, Any]]:
    """Fetch FLAME's STIX bundle with caching (same pattern as flame_client)."""
    # Check cache
    if _STIX_CACHE.exists() and _STIX_CACHE_META.exists():
        try:
            with open(_STIX_CACHE_META, "r") as fh:
                meta = json.load(fh)
            ttl = float(cfg.get("flame.cache_ttl_hours", 24)) * 3600
            if (time.time() - meta.get("fetched_at", 0)) < ttl:
                with open(_STIX_CACHE, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                print(f"    FLAME STIX cache hit ({len(data.get('objects', []))} objects)")
                return data
        except (json.JSONDecodeError, OSError, KeyError):
            pass

    # Fetch from network
    url = cfg.get("flame.stix_bundle_url", _DEFAULT_STIX_URL)
    print(f"    Fetching FLAME STIX bundle from {url}...")
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()

        # Cache
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with open(_STIX_CACHE, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with open(_STIX_CACHE_META, "w") as fh:
            json.dump({"fetched_at": time.time()}, fh)

        print(f"    Fetched {len(data.get('objects', []))} FLAME STIX objects")
        return data
    except requests.RequestException as exc:
        print(f"[!] Could not fetch FLAME STIX bundle: {exc}")

    # Stale cache fallback
    if _STIX_CACHE.exists():
        try:
            with open(_STIX_CACHE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            print(f"    Using stale FLAME STIX cache ({len(data.get('objects', []))} objects)")
            return data
        except (json.JSONDecodeError, OSError):
            pass

    return None


def extract_flame_attack_patterns(
    bundle_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Extract attack-pattern objects from FLAME bundle, keyed by TP ID."""
    ap_map = {}  # tp_id -> stix object dict
    for obj in bundle_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        # Extract TP ID from external_references
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "FLAME Project":
                desc = ref.get("description", "")
                if desc.startswith("Threat Path TP-"):
                    tp_id = desc.replace("Threat Path ", "")
                    ap_map[tp_id] = obj
                    break
    return ap_map


# ---------------------------------------------------------------------------
# Bundle Assembly
# ---------------------------------------------------------------------------

def write_bundle(objects: List, output_path: str, label: str) -> None:
    """Write a STIX bundle and validate."""
    bundle_id = det_id("bundle", f"domain-intel-{label}")
    
    # Bypass stix2.Bundle.serialize() due to O(N^2) duplicate ID checks 
    # that cause the script to hang for hours on large datasets.
    bundle_data = {
        "type": "bundle",
        "id": bundle_id,
        "objects": [json.loads(obj.serialize()) if hasattr(obj, "serialize") else obj for obj in objects]
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(bundle_data, f, indent=4)
    print(f"[+] {label} bundle -> {output_path} ({len(objects)} objects)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="STIX 2.1 Export")
    parser.add_argument("--input", default="data/dea_domains_enriched.csv",
                        help="Main domain input CSV")
    parser.add_argument("--output", default="data/domain_intel_bundle.json",
                        help="Standalone STIX bundle output")
    parser.add_argument("--flame-output",
                        default="data/domain_intel_flame_bundle.json",
                        help="FLAME-enriched STIX bundle output")
    parser.add_argument("--suspicious-asns", default="data/suspicious_asns.csv")
    parser.add_argument("--vpn-asns", default="data/vpn_asns.csv")
    parser.add_argument("--tor-nodes", default="data/tor_nodes.csv")
    parser.add_argument("--tor-asns", default="data/tor_asns.csv")
    parser.add_argument("--shodan", default="data/shodan_intelligence.csv")
    parser.add_argument("--no-flame", action="store_true",
                        help="Skip FLAME integration")
    args = parser.parse_args()

    print("[*] domain_intel STIX 2.1 Export")

    identity = build_identity()

    # Collect all indicators
    all_indicators: List[stix2.Indicator] = []

    # Domains
    all_indicators.extend(process_domains(
        args.input,
        ["malicious-activity", "anomalous-activity"],
        confidence=60
    ))

    # Suspicious ASNs
    all_indicators.extend(process_asns(
        args.suspicious_asns,
        ["malicious-activity", "hosting-provider"],
        confidence=70
    ))

    # VPN ASNs
    all_indicators.extend(process_asns(
        args.vpn_asns,
        ["anonymization", "vpn-provider"],
        confidence=50
    ))

    # Tor ASNs
    all_indicators.extend(process_asns(
        args.tor_asns,
        ["anonymization", "tor-network"],
        confidence=90
    ))

    # Tor Nodes
    all_indicators.extend(process_ips(
        args.tor_nodes,
        ["anonymization", "tor-exit"],
        confidence=95
    ))

    # Shodan
    all_indicators.extend(process_shodan(args.shodan))

    print(f"\n[*] Total indicators: {len(all_indicators)}")

    # Build indicator lookup by pattern value (for FLAME linking)
    indicator_by_domain: Dict[str, stix2.Indicator] = {}
    for ind in all_indicators:
        pattern = ind.pattern
        if "domain-name:value" in pattern:
            # Extract domain from pattern
            domain = pattern.split("'")[1] if "'" in pattern else ""
            if domain:
                indicator_by_domain[domain.lower()] = ind

    # --- Standalone bundle (backward compatible) ---
    standalone_objects = [identity] + all_indicators
    write_bundle(standalone_objects, args.output, "standalone")

    # --- FLAME-enriched bundle ---
    if args.no_flame:
        print("[*] FLAME integration skipped (--no-flame)")
        return

    print("\n[*] FLAME Integration...")
    flame_tp_map = load_flame_tp_mapping()
    print(f"    {len(flame_tp_map)} domains have FLAME TP mappings")

    flame_bundle = fetch_flame_stix_bundle()
    if not flame_bundle:
        print("[!] FLAME STIX bundle unavailable — skipping enriched export")
        return

    flame_aps = extract_flame_attack_patterns(flame_bundle)
    print(f"    {len(flame_aps)} FLAME attack-patterns available")

    if not flame_aps:
        print("[!] No FLAME attack-patterns found — skipping enriched export")
        return

    # Build relationships: indicator --indicates--> attack-pattern
    relationships: List[stix2.Relationship] = []
    linked_aps: Set[str] = set()  # Track which APs we actually reference

    for domain, tp_ids in flame_tp_map.items():
        ind = indicator_by_domain.get(domain)
        if not ind:
            continue
        for tp_id in tp_ids:
            ap_dict = flame_aps.get(tp_id)
            if not ap_dict:
                continue
            ap_id = ap_dict["id"]
            linked_aps.add(tp_id)
            rel = build_relationship(ind.id, ap_id, "indicates")
            relationships.append(rel)

    print(f"    {len(relationships)} indicator->attack-pattern relationships")
    print(f"    {len(linked_aps)} unique attack-patterns referenced")

    # Build enriched bundle
    # Include identity + indicators + FLAME APs (deduplicated) + relationships
    # Also include any FLAME identity and relationships from their bundle
    enriched_objects = [identity] + all_indicators

    # Add referenced FLAME objects (attack-patterns, identity, relationships)
    seen_ids = {obj.id for obj in enriched_objects}
    for obj in flame_bundle.get("objects", []):
        obj_id = obj.get("id", "")
        if obj_id in seen_ids:
            continue
        # Include attack-patterns, identity, and FLAME relationships
        obj_type = obj.get("type", "")
        if obj_type in ("attack-pattern", "identity", "relationship"):
            enriched_objects.append(obj)
            seen_ids.add(obj_id)

    # Add our new relationships
    enriched_objects.extend(relationships)

    write_bundle(enriched_objects, args.flame_output, "flame-enriched")

    print("\n[*] STIX Export Complete.")


if __name__ == "__main__":
    main()
