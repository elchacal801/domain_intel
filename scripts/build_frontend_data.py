#!/usr/bin/env python3
"""
build_frontend_data.py

Generates JSON data files for the investigation frontend from pipeline CSVs.
Replaces build_dashboard_data.py and build_investigate_index.py with a unified
output suitable for the React investigation UI.

Outputs (to --output-dir, default docs/data/):
  domains.json             — all domain data keyed by domain name
  fingerprint_matches.json — flat list of all fingerprint matches
  clusters.json            — infrastructure cluster graph (nodes + edges)
  stats.json               — summary statistics for dashboard KPIs

Required inputs:
  --probed          data/dea_domains_probed.csv
  --fingerprints    data/fingerprint_matches.csv

Optional inputs (warn if missing, don't crash):
  data/ai_classifications.csv
  data/ai_typosquats.csv
  data/shodan_intelligence.csv
  data/phishtank_matches.csv
"""

import argparse
import csv
import fnmatch
import ipaddress
import json
import logging
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

try:
    import yaml
except ImportError:
    yaml = None

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# Default paths
DEFAULT_PROBED = "data/dea_domains_probed.csv"
DEFAULT_FINGERPRINTS = "data/fingerprint_matches.csv"
DEFAULT_OUTPUT_DIR = "docs/data"
DEFAULT_MIN_CLUSTER_SIZE = 3

# Optional file definitions: name -> (path, fields to extract, prefix for merged keys)
OPTIONAL_FILES = {
    "ai_classifications": {
        "path": "data/ai_classifications.csv",
        "fields": ["category", "confidence"],
        "prefix": "ai_",
    },
    "ai_typosquats": {
        "path": "data/ai_typosquats.csv",
        "fields": ["target"],
        "prefix": "typosquat_",
    },
    "shodan_intelligence": {
        "path": "data/shodan_intelligence.csv",
        "fields": ["ports", "vulns", "os", "tags", "hostnames"],
        "prefix": "shodan_",
    },
    "phishtank_matches": {
        "path": "data/phishtank_matches.csv",
        "fields": ["phishtank_url", "urlhaus_threat", "phishtank_match"],
        "prefix": "phishtank_",
    },
    "virustotal_intelligence": {
        "path": "data/virustotal_intelligence.csv",
        "fields": ["vt_malicious_count", "vt_undetected_count", "vt_last_analysis"],
        "prefix": "",
    },
    "openclaw_exposed": {
        "path": "data/openclaw_exposed.csv",
        "fields": ["agent_type", "exposure_level", "model_id"],
        "prefix": "openclaw_",
    },
    "domain_registrars": {
        "path": "data/domain_registrars.csv",
        "fields": ["registrar", "creation_date", "expiration_date"],
        "prefix": "whois_",
    },
    "enriched_candidates": {
        "path": "data/enriched_candidates.csv",
        "fields": ["st_registrar_changes", "st_dns_history_count"],
        "prefix": "",
    },
}


# ---------------------------------------------------------------------------
# CSV loading
# ---------------------------------------------------------------------------

def load_probed_csv(filepath):
    """
    Load the probed domains CSV into a dict keyed by domain name.
    Each value is a dict of all column values.
    Returns empty dict if file missing or empty.
    """
    if not os.path.exists(filepath):
        log.warning("Probed CSV not found: %s", filepath)
        return {}

    domains = {}
    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get("domain", "").strip()
            if domain:
                domains[domain] = dict(row)

    if not domains:
        log.warning("Probed CSV is empty: %s", filepath)
    else:
        log.info("Loaded %d domains from %s", len(domains), filepath)

    return domains


def load_fingerprint_matches(filepath):
    """
    Load fingerprint matches CSV grouped by domain.
    Returns dict: domain -> list of match dicts.
    Returns empty dict if file missing or empty.
    """
    if not os.path.exists(filepath):
        log.warning("Fingerprint matches CSV not found: %s", filepath)
        return {}

    grouped = defaultdict(list)
    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get("domain", "").strip()
            if domain:
                grouped[domain].append({
                    "fp_id": row.get("fp_id", ""),
                    "fp_name": row.get("fp_name", ""),
                    "confidence": row.get("confidence", ""),
                    "flame_tp_ids": row.get("flame_tp_ids", ""),
                    "evidence": row.get("evidence", ""),
                })

    result = dict(grouped)
    if not result:
        log.warning("Fingerprint matches CSV is empty: %s", filepath)
    else:
        log.info("Loaded fingerprint matches for %d domains from %s",
                 len(result), filepath)

    return result


def load_optional_csv(filepath, fields):
    """
    Load an optional enrichment CSV keyed by domain.
    Only extracts the specified fields.
    Returns empty dict if file missing.
    """
    if not os.path.exists(filepath):
        log.warning("Optional CSV not found (skipping): %s", filepath)
        return {}

    result = {}
    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get("domain", "").strip()
            if domain:
                extracted = {}
                for field in fields:
                    val = row.get(field, "")
                    if val:
                        extracted[field] = val
                if extracted:
                    result[domain] = extracted

    log.info("Loaded optional data for %d domains from %s", len(result), filepath)
    return result


def merge_optional_data(domains, optional_data, prefix):
    """
    Merge optional enrichment data into domains dict.
    Keys are prefixed with the given prefix to avoid collisions.
    """
    merged_count = 0
    for domain, extra in optional_data.items():
        if domain in domains:
            for key, val in extra.items():
                domains[domain][prefix + key] = val
            merged_count += 1
    if merged_count:
        log.info("Merged %d domains with prefix '%s'", merged_count, prefix)


# ---------------------------------------------------------------------------
# Risk score computation
# ---------------------------------------------------------------------------

def _safe_float(val, default=0.0):
    """Safely parse a value to float."""
    if val is None or val == "":
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def compute_risk_score(domain_data):
    """
    Compute a composite risk score (0-100) from multiple signal axes.

    Signal weights:
      - Fingerprint confidence (max across matches): 25%
      - VT malicious count (normalized 0-100):       20%
      - OpenSanctions match score:                   15%
      - RBL hits count:                              10%
      - PhishTank/URLhaus match:                     10%
      - AI typosquat presence:                       10%
      - Domain age < 30 days:                        10%

    Returns (score: int 0-100, level: str).
    """
    signals = {}

    # 1. Fingerprint confidence (already 0-100)
    matches = domain_data.get("matches", [])
    if matches:
        max_conf = max(_safe_float(m.get("confidence", 0)) for m in matches)
        signals["fingerprint"] = min(max_conf, 100.0)
    else:
        signals["fingerprint"] = 0.0

    # 2. VT malicious count (cap at 20 engines = 100%)
    vt_count = _safe_float(domain_data.get("vt_malicious_count", 0))
    signals["virustotal"] = min(vt_count / 20.0 * 100.0, 100.0)

    # 3. OpenSanctions match score (already 0-100 range)
    os_score = _safe_float(domain_data.get("os_match_score", 0))
    signals["opensanctions"] = min(os_score, 100.0)

    # 4. RBL hits (cap at 5 hits = 100%)
    rbl = _safe_float(domain_data.get("rbl_hits", 0))
    signals["rbl"] = min(rbl / 5.0 * 100.0, 100.0)

    # 5. PhishTank match (binary)
    pt = domain_data.get("phishtank_match", domain_data.get("phishtank_phishtank_match", ""))
    signals["phishtank"] = 100.0 if str(pt).strip().lower() in ("true", "1", "yes") else 0.0

    # 6. AI typosquat (binary — has a target)
    typo_target = domain_data.get("typosquat_target", "")
    signals["typosquat"] = 100.0 if typo_target else 0.0

    # 7. Domain age < 30 days
    age = _safe_float(domain_data.get("age_days", 365))
    if age <= 0:
        signals["young_domain"] = 0.0
    elif age < 30:
        signals["young_domain"] = (1.0 - age / 30.0) * 100.0
    else:
        signals["young_domain"] = 0.0

    # Weighted composite
    weights = {
        "fingerprint": 0.25,
        "virustotal": 0.20,
        "opensanctions": 0.15,
        "rbl": 0.10,
        "phishtank": 0.10,
        "typosquat": 0.10,
        "young_domain": 0.10,
    }
    score = sum(signals[k] * weights[k] for k in weights)
    score = int(round(min(max(score, 0), 100)))

    if score >= 75:
        level = "Critical"
    elif score >= 50:
        level = "High"
    elif score >= 25:
        level = "Medium"
    else:
        level = "Low"

    return score, level, signals


# ---------------------------------------------------------------------------
# Infrastructure pivot index
# ---------------------------------------------------------------------------

MAX_INDEX_ENTRIES = 200  # cap domain list per key


def _compute_entity_stats(domain_names, domains_dict):
    """Compute entity statistics for a set of domains sharing infrastructure.

    Args:
        domain_names: list of domain name strings
        domains_dict: the full domains dict keyed by domain name

    Returns:
        dict with keys: os_hits, icij_hits, gleif_active, unique_registrants, total
    """
    os_hits = 0
    icij_hits = 0
    gleif_active = 0
    registrants = set()

    for d in domain_names:
        data = domains_dict.get(d, {})

        os_score = str(data.get("os_match_score", "")).strip()
        if os_score:
            try:
                if float(os_score) > 0:
                    os_hits += 1
            except (ValueError, TypeError):
                pass

        icij = str(data.get("icij_entity_match", "")).strip()
        if icij:
            icij_hits += 1

        gleif = str(data.get("gleif_status", "")).strip().upper()
        if gleif == "ACTIVE":
            gleif_active += 1

        reg = str(data.get("registrant_org", "")).strip()
        if reg:
            registrants.add(reg)

    return {
        "os_hits": os_hits,
        "icij_hits": icij_hits,
        "gleif_active": gleif_active,
        "unique_registrants": len(registrants),
        "total": len(domain_names),
    }


# Map from infra_index category name to match_shared_provider value_type.
# Categories without a corresponding provider check use None.
_CATEGORY_TO_PROVIDER_TYPE = {
    "mx": "mx",
    "asn": "asn",
    "a_record": "ip",
    "registrar": None,
    "fp": None,
}


def build_infra_index(domains, fp_matches):
    """
    Build a reverse-lookup index for infrastructure pivot search.

    Returns dict with keys: asn, mx, registrar, fp, a_record.
    Each maps a value to an enriched dict containing:
      - domains: list of domain names (capped at MAX_INDEX_ENTRIES)
      - private: bool — True if infrastructure is NOT a known shared provider
      - entity_stats: dict with os_hits, icij_hits, gleif_active,
                      unique_registrants, total
    Only buckets with >= 2 domains are included.
    """
    asn_idx = defaultdict(list)
    mx_idx = defaultdict(list)
    reg_idx = defaultdict(list)
    fp_idx = defaultdict(list)
    a_record_idx = defaultdict(list)

    for domain, data in domains.items():
        asn = str(data.get("asn", "")).strip()
        if asn:
            asn_idx[asn].append(domain)

        mx = str(data.get("primary_mx", "")).strip()
        if mx:
            mx_idx[mx].append(domain)

        reg = str(data.get("registrant_org", "")).strip()
        if reg:
            reg_idx[reg].append(domain)

        a_record = str(data.get("a_record", "")).strip()
        if a_record:
            a_record_idx[a_record].append(domain)

    for domain, match_list in fp_matches.items():
        for m in match_list:
            fp_id = m.get("fp_id", "")
            if fp_id:
                fp_idx[fp_id].append(domain)

    # Load shared infra config for private flag determination
    si_config = load_shared_infra_config()

    def _enrich(index, category):
        result = {}
        provider_type = _CATEGORY_TO_PROVIDER_TYPE.get(category)
        for k, v in index.items():
            unique = sorted(set(v))
            if len(unique) < 2:
                continue
            domain_list = unique[:MAX_INDEX_ENTRIES]

            # Determine if this is private (not a known shared provider)
            if provider_type and si_config:
                is_shared = match_shared_provider(k, provider_type, si_config) is not None
            else:
                is_shared = False
            private = not is_shared

            result[k] = {
                "domains": domain_list,
                "private": private,
                "entity_stats": _compute_entity_stats(domain_list, domains),
            }
        return result

    return {
        "asn": _enrich(asn_idx, "asn"),
        "mx": _enrich(mx_idx, "mx"),
        "registrar": _enrich(reg_idx, "registrar"),
        "fp": _enrich(fp_idx, "fp"),
        "a_record": _enrich(a_record_idx, "a_record"),
    }


# ---------------------------------------------------------------------------
# Shared infrastructure detection
# ---------------------------------------------------------------------------

def load_shared_infra_config(path=None):
    """
    Load the shared infrastructure YAML config.

    Parses IP ranges into ipaddress.ip_network objects for efficient matching.
    Returns structured config dict, or empty config on failure.
    """
    if path is None:
        path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "config", "shared_infrastructure.yaml",
        )

    if yaml is None:
        log.warning("PyYAML not installed; shared infra detection disabled")
        return {}

    if not os.path.exists(path):
        log.warning("Shared infrastructure config not found: %s", path)
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    except Exception as exc:
        log.warning("Failed to load shared infra config: %s", exc)
        return {}

    # Parse IP ranges into ipaddress objects
    for provider_id, provider in config.get("providers", {}).items():
        parsed_ranges = []
        for cidr in provider.get("ip_ranges", []):
            try:
                parsed_ranges.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as exc:
                log.warning("Invalid CIDR %s in provider %s: %s", cidr, provider_id, exc)
        provider["_parsed_ip_ranges"] = parsed_ranges

    log.info("Loaded shared infra config with %d providers from %s",
             len(config.get("providers", {})), path)
    return config


def match_shared_provider(value, value_type, config):
    """
    Check whether a value matches a known shared infrastructure provider.

    Args:
        value: the string to check (MX hostname, IP address, NS hostname, or ASN)
        value_type: one of "mx", "ip", "ns", or "asn"
        config: shared infra config dict from load_shared_infra_config()

    Returns:
        (provider_id, provider_label, category) or None
    """
    if not config or not value:
        return None

    providers = config.get("providers", {})
    value_lower = value.strip().lower()

    for provider_id, provider in providers.items():
        if value_type == "mx":
            for pattern in provider.get("mx_patterns", []):
                if fnmatch.fnmatch(value_lower, pattern.lower()):
                    return (provider_id, provider.get("label", provider_id),
                            provider.get("category", ""))

        elif value_type == "ip":
            try:
                addr = ipaddress.ip_address(value.strip())
            except ValueError:
                return None
            for net in provider.get("_parsed_ip_ranges", []):
                if addr in net:
                    return (provider_id, provider.get("label", provider_id),
                            provider.get("category", ""))

        elif value_type == "ns":
            for pattern in provider.get("ns_patterns", []):
                if fnmatch.fnmatch(value_lower, pattern.lower()):
                    return (provider_id, provider.get("label", provider_id),
                            provider.get("category", ""))

        elif value_type == "asn":
            for asn_val in provider.get("asn_list", []):
                if value_lower == str(asn_val).strip().lower():
                    return (provider_id, provider.get("label", provider_id),
                            provider.get("category", ""))

    return None


def compute_cluster_confidence(cluster_size, shared_match, domains_in_cluster,
                               all_domains, config, uniqueness_bonus=0):
    """
    Score how likely a cluster represents genuine shared-operator infrastructure.

    Args:
        cluster_size: number of domains in the cluster
        shared_match: result from match_shared_provider() or None
        domains_in_cluster: set of domain names in this cluster
        all_domains: full domains dict (domain -> data)
        config: shared infra config dict
        uniqueness_bonus: extra score for MX hostname uniqueness in IP clusters

    Returns:
        (score: int 0-100, level: str, breakdown: dict)
    """
    base = 80

    # Size penalty from config (largest matching threshold)
    size_penalty = 0
    size_penalties = config.get("size_penalties", [])
    for threshold in sorted(size_penalties, key=lambda x: x["above"], reverse=True):
        if cluster_size > threshold["above"]:
            size_penalty = -threshold["penalty"]
            break

    # Shared infrastructure penalty
    shared_penalty = -35 if shared_match else 0

    # ASN diversity penalty
    unique_asns = set()
    for d in domains_in_cluster:
        ddata = all_domains.get(d, {})
        asn_val = str(ddata.get("asn", "")).strip()
        if asn_val:
            unique_asns.add(asn_val)

    diversity_penalty = 0
    if len(unique_asns) > 1:
        unique_asn_ratio = len(unique_asns) / cluster_size
        if unique_asn_ratio > 0.7:
            diversity_penalty = -15
        elif unique_asn_ratio > 0.4:
            diversity_penalty = -8

    score = base + size_penalty + shared_penalty + diversity_penalty + uniqueness_bonus
    score = max(0, min(100, score))

    # Map to level using thresholds from config
    high_threshold = config.get("confidence_thresholds", {}).get("high", 70)
    medium_threshold = config.get("confidence_thresholds", {}).get("medium", 40)

    if score >= high_threshold:
        level = "high"
    elif score >= medium_threshold:
        level = "medium"
    else:
        level = "low"

    breakdown = {
        "base": base,
        "size_penalty": size_penalty,
        "shared_penalty": shared_penalty,
        "diversity_penalty": diversity_penalty,
        "uniqueness_bonus": uniqueness_bonus,
        "cluster_size": cluster_size,
        "unique_asns": len(unique_asns),
    }

    return score, level, breakdown


def compute_a_record_cluster_confidence(cluster_size, shared_match, domains_in_cluster,
                                        all_domains, config):
    """
    Inverted confidence for A-record clusters: large unknown = high signal.

    Unlike MX/IP clusters where large size + unknown provider gets penalized
    (probably a shared provider we don't know about), A-record clusters use
    inverted semantics:
      - Large size + unknown provider = HIGH confidence (campaign infrastructure)
      - Large size + known CDN = LOW confidence (shared hosting)

    Args:
        cluster_size: number of domains in the cluster
        shared_match: result from match_shared_provider() or None
        domains_in_cluster: set of domain names in this cluster
        all_domains: full domains dict (domain -> data)
        config: shared infra config dict

    Returns:
        (score: int 0-100, level: str, breakdown: dict)
    """
    if shared_match:
        # Known CDN/hosting: always low
        base = 25
        size_bonus = 0
    else:
        # Unknown provider: scale UP with size
        base = 50
        size_bonus = 0
        bonuses = config.get("a_record_size_bonuses", [
            {"above": 100, "bonus": 30},
            {"above": 50, "bonus": 20},
            {"above": 20, "bonus": 15},
            {"above": 10, "bonus": 10},
            {"above": 5, "bonus": 5},
        ])
        for threshold in sorted(bonuses, key=lambda x: x["above"], reverse=True):
            if cluster_size > threshold["above"]:
                size_bonus = threshold["bonus"]
                break

    # ASN homogeneity bonus (all domains on same ASN = more likely campaign infra)
    unique_asns = set()
    for d in domains_in_cluster:
        ddata = all_domains.get(d, {})
        asn_val = str(ddata.get("a_record_asn", ddata.get("asn", ""))).strip()
        if asn_val:
            unique_asns.add(asn_val)

    homogeneity_bonus = 0
    if not shared_match and len(unique_asns) == 1 and cluster_size >= 3:
        homogeneity_bonus = 10

    score = max(0, min(100, base + size_bonus + homogeneity_bonus))

    high_threshold = config.get("confidence_thresholds", {}).get("high", 70)
    medium_threshold = config.get("confidence_thresholds", {}).get("medium", 40)
    if score >= high_threshold:
        level = "high"
    elif score >= medium_threshold:
        level = "medium"
    else:
        level = "low"

    breakdown = {
        "base": base,
        "size": size_bonus,
        "shared_infra": -25 if shared_match else 0,  # delta from unknown base (50) to known base (25)
        "homogeneity": homogeneity_bonus,
    }

    return score, level, breakdown


# ---------------------------------------------------------------------------
# Cluster computation
# ---------------------------------------------------------------------------

def compute_clusters(domains, min_cluster_size=DEFAULT_MIN_CLUSTER_SIZE,
                     shared_infra_config=None):
    """
    Group domains by shared infrastructure into a graph structure.

    Link types:
      - Shared MX host (primary_mx)
      - Shared IP (mx_ip)
      - Shared registrar + nameservers (registrant_org + nameservers)

    Returns: {nodes: [...], edges: [...]}
    """
    # Collect groupings
    mx_groups = defaultdict(set)      # mx_host -> set of domains
    ip_groups = defaultdict(set)      # ip -> set of domains
    regns_groups = defaultdict(set)   # (registrant_org, nameservers) -> set of domains
    a_record_groups = defaultdict(set)  # a_record IP -> set of domains

    for domain, data in domains.items():
        mx = data.get("primary_mx", "").strip()
        if mx:
            mx_groups[mx].add(domain)

        ip = data.get("mx_ip", "").strip()
        if ip:
            ip_groups[ip].add(domain)

        reg = data.get("registrant_org", "").strip()
        ns = data.get("nameservers", "").strip()
        if reg and ns:
            regns_groups[(reg, ns)].add(domain)

        a_record = data.get("a_record", "").strip()
        if a_record:
            a_record_groups[a_record].add(domain)

    nodes = {}  # id -> node dict (dedup)
    edges = []

    # Use empty dict if no shared infra config provided
    si_config = shared_infra_config or {}

    def add_infra_node(node_id, node_type, label, domain_set,
                       shared_match=None, confidence_score=0,
                       confidence_level="low", confidence_breakdown=None,
                       resolution_method=None, extra=None):
        if node_id not in nodes:
            node = {
                "id": node_id,
                "type": node_type,
                "label": label,
                "size": min(5 + len(domain_set), 30),
                "shared_infra": bool(shared_match),
                "provider": shared_match[0] if shared_match else None,
                "provider_label": shared_match[1] if shared_match else None,
                "provider_category": shared_match[2] if shared_match else None,
                "confidence": confidence_score,
                "confidence_level": confidence_level,
                "confidence_breakdown": confidence_breakdown,
                "resolution_method": resolution_method,
                "domain_count": len(domain_set),
            }
            if extra:
                node.update(extra)
            nodes[node_id] = node

    def add_domain_node(domain):
        node_id = f"dom:{domain}"
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "type": "domain",
                "label": domain,
                "size": 3,
            }
        return node_id

    # Process MX clusters
    for mx_host, domain_set in mx_groups.items():
        if len(domain_set) >= min_cluster_size:
            infra_id = f"mx:{mx_host}"

            shared_match = match_shared_provider(mx_host, "mx", si_config) if si_config else None
            confidence_score, confidence_level, breakdown = compute_cluster_confidence(
                cluster_size=len(domain_set),
                shared_match=shared_match,
                domains_in_cluster=domain_set,
                all_domains=domains,
                config=si_config,
                uniqueness_bonus=0,
            )

            add_infra_node(infra_id, "mx_host", mx_host, domain_set,
                           shared_match=shared_match,
                           confidence_score=confidence_score,
                           confidence_level=confidence_level,
                           confidence_breakdown=breakdown,
                           resolution_method="mx_host")
            for d in domain_set:
                dom_id = add_domain_node(d)
                edges.append({"source": dom_id, "target": infra_id})

    # Process IP clusters
    for ip, domain_set in ip_groups.items():
        if len(domain_set) >= min_cluster_size:
            infra_id = f"ip:{ip}"

            shared_match = match_shared_provider(ip, "ip", si_config) if si_config else None

            # Collect all primary_mx values once for both uniqueness bonus
            # and related_mx_hosts output
            related_mx = set()
            for d in domain_set:
                pmx = domains.get(d, {}).get("primary_mx", "").strip()
                if pmx:
                    related_mx.add(pmx)

            # MX hostname uniqueness bonus: if not shared and all domains
            # share the same primary_mx, award +10
            uniqueness_bonus = 0
            if not shared_match and len(related_mx) == 1:
                uniqueness_bonus = 10

            confidence_score, confidence_level, breakdown = compute_cluster_confidence(
                cluster_size=len(domain_set),
                shared_match=shared_match,
                domains_in_cluster=domain_set,
                all_domains=domains,
                config=si_config,
                uniqueness_bonus=uniqueness_bonus,
            )

            add_infra_node(infra_id, "ip", ip, domain_set,
                           shared_match=shared_match,
                           confidence_score=confidence_score,
                           confidence_level=confidence_level,
                           confidence_breakdown=breakdown,
                           resolution_method="mx_ip",
                           extra={"related_mx_hosts": sorted(related_mx)})
            for d in domain_set:
                dom_id = add_domain_node(d)
                edges.append({"source": dom_id, "target": infra_id})

    # Process registrar+NS clusters
    for (reg, ns), domain_set in regns_groups.items():
        if len(domain_set) >= min_cluster_size:
            infra_id = f"regns:{reg}|{ns}"
            label = f"{reg} / {ns}"

            # Match individual nameservers against shared infra config
            shared_match = None
            if si_config:
                ns_parts = [s.strip() for s in ns.replace(",", ";").split(";") if s.strip()]
                for ns_entry in ns_parts:
                    shared_match = match_shared_provider(ns_entry, "ns", si_config)
                    if shared_match:
                        break

            confidence_score, confidence_level, breakdown = compute_cluster_confidence(
                cluster_size=len(domain_set),
                shared_match=shared_match,
                domains_in_cluster=domain_set,
                all_domains=domains,
                config=si_config,
                uniqueness_bonus=0,
            )

            add_infra_node(infra_id, "registrar_ns", label, domain_set,
                           shared_match=shared_match,
                           confidence_score=confidence_score,
                           confidence_level=confidence_level,
                           confidence_breakdown=breakdown,
                           resolution_method="registration")
            for d in domain_set:
                dom_id = add_domain_node(d)
                edges.append({"source": dom_id, "target": infra_id})

    # Process A-record clusters
    for a_ip, domain_set in a_record_groups.items():
        if len(domain_set) >= min_cluster_size:
            infra_id = f"a_ip:{a_ip}"

            # Get cluster ASN from any domain's a_record_asn
            cluster_asn = ""
            cluster_asn_name = ""
            for d in domain_set:
                ddata = domains.get(d, {})
                asn_val = str(ddata.get("a_record_asn", "")).strip()
                if asn_val:
                    cluster_asn = asn_val
                    cluster_asn_name = str(ddata.get("a_record_asn_name", "")).strip()
                    break

            # Match ASN via shared infra config
            shared_match = None
            if si_config and cluster_asn:
                shared_match = match_shared_provider(cluster_asn, "asn", si_config)

            # Score with inverted A-record confidence
            confidence_score, confidence_level, breakdown = compute_a_record_cluster_confidence(
                cluster_size=len(domain_set),
                shared_match=shared_match,
                domains_in_cluster=domain_set,
                all_domains=domains,
                config=si_config,
            )

            add_infra_node(infra_id, "a_record_ip", a_ip, domain_set,
                           shared_match=shared_match,
                           confidence_score=confidence_score,
                           confidence_level=confidence_level,
                           confidence_breakdown=breakdown,
                           resolution_method="a_record",
                           extra={
                               "hosting_asn": cluster_asn,
                               "hosting_asn_name": cluster_asn_name,
                           })
            for d in domain_set:
                dom_id = add_domain_node(d)
                edges.append({"source": dom_id, "target": infra_id})

    return {"nodes": list(nodes.values()), "edges": edges}


# ---------------------------------------------------------------------------
# Stats computation
# ---------------------------------------------------------------------------

def _extract_tld(domain):
    """Extract the TLD (e.g. '.com') from a domain name."""
    if "." in domain:
        return "." + domain.rsplit(".", 1)[-1]
    return domain


def compute_stats(domains, fp_matches, clusters):
    """
    Compute summary statistics for the dashboard.

    Returns dict with: total_domains, matched_domains, total_clusters,
    unique_fingerprints, tld_distribution (top 20), top_fingerprints (top 10),
    last_updated (ISO timestamp).
    """
    # Count infrastructure (non-domain) nodes as clusters
    infra_nodes = [n for n in clusters.get("nodes", []) if n.get("type") != "domain"]
    total_clusters = len(infra_nodes)

    # Unique fingerprints
    all_fp_ids = set()
    fp_counter = Counter()
    for match_list in fp_matches.values():
        for m in match_list:
            fp_id = m.get("fp_id", "")
            fp_name = m.get("fp_name", fp_id)
            if fp_id:
                all_fp_ids.add(fp_id)
                fp_counter[fp_name] += 1

    # TLD distribution
    tld_counter = Counter()
    for domain in domains:
        tld_counter[_extract_tld(domain)] += 1

    # Count cluster confidence distribution
    confidence_dist = {"high": 0, "medium": 0, "low": 0}
    shared_count = 0
    for node in clusters.get("nodes", []):
        if node.get("type") != "domain":
            level = node.get("confidence_level", "low")
            if level in confidence_dist:
                confidence_dist[level] += 1
            if node.get("shared_infra"):
                shared_count += 1

    stats = {
        "total_domains": len(domains),
        "matched_domains": len(fp_matches),
        "total_clusters": total_clusters,
        "unique_fingerprints": len(all_fp_ids),
        "tld_distribution": dict(tld_counter.most_common(20)),
        "top_fingerprints": dict(fp_counter.most_common(10)),
        "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    stats["cluster_confidence_distribution"] = confidence_dist
    stats["shared_infra_clusters"] = shared_count

    # Count A-record clusters
    a_record_cluster_count = sum(
        1 for n in clusters.get("nodes", [])
        if n.get("type") == "a_record_ip"
    )
    stats["a_record_clusters"] = a_record_cluster_count

    return stats


# ---------------------------------------------------------------------------
# Output building
# ---------------------------------------------------------------------------

def _shard_key(domain):
    """Derive the shard key from a domain name (first character, lowered)."""
    if not domain:
        return "misc"
    first = domain[0].lower()
    if first.isalpha():
        return first
    if first.isdigit():
        return first
    return "misc"


def build_outputs(probed_path, fingerprints_path, output_dir,
                  min_cluster_size=DEFAULT_MIN_CLUSTER_SIZE,
                  optional_files=None):
    """
    Main orchestrator: load data, compute derived structures, write JSON files.

    Domains are written as sharded files (domains_{key}.json) to stay under
    GitHub's 100 MB file size limit. A domain_shards.json manifest lists all
    available shard keys.

    Parameters:
        probed_path: path to dea_domains_probed.csv
        fingerprints_path: path to fingerprint_matches.csv
        output_dir: directory for JSON output files
        min_cluster_size: minimum domains to form a cluster
        optional_files: dict of optional file configs to merge
    """
    if optional_files is None:
        optional_files = {}

    # Load shared infrastructure config
    shared_infra_config = load_shared_infra_config()

    # Load required data
    domains = load_probed_csv(probed_path)
    fp_matches = load_fingerprint_matches(fingerprints_path)

    # Load and merge optional data
    for name, config in optional_files.items():
        opt_data = load_optional_csv(config["path"], config["fields"])
        if opt_data:
            merge_optional_data(domains, opt_data, config.get("prefix", ""))

    # Attach fingerprint matches to domain records
    for domain, data in domains.items():
        data["matches"] = fp_matches.get(domain, [])

    # Compute risk scores
    for domain, data in domains.items():
        score, level, signals = compute_risk_score(data)
        data["risk_score"] = score
        data["risk_level"] = level
        data["risk_signals"] = signals

    # Compute derived structures
    clusters = compute_clusters(domains, min_cluster_size=min_cluster_size,
                                shared_infra_config=shared_infra_config)

    # Add resolution chain to domain records.
    # NOTE: Resolution chains are intentionally MX-only (domain -> MX -> IP).
    # NS paths are excluded per the design spec because NS infrastructure is
    # already captured separately in registrar+NS clusters.
    for domain, data in domains.items():
        primary_mx = data.get("primary_mx", "").strip()
        mx_ip = data.get("mx_ip", "").strip()
        if primary_mx:
            mx_match = match_shared_provider(primary_mx, "mx", shared_infra_config) if shared_infra_config else None
            if mx_ip:
                path = [domain, "MX", primary_mx, "A", mx_ip]
            else:
                path = [domain, "MX", primary_mx]
            data["resolution_chain"] = {
                "path": path,
                "mx_provider": mx_match[0] if mx_match else None,
                "mx_provider_label": mx_match[1] if mx_match else None,
                "mx_shared": bool(mx_match),
            }

        # A-record resolution chain
        a_record = data.get("a_record", "").strip()
        if a_record:
            a_asn = data.get("a_record_asn", "").strip()
            a_shared = None
            if shared_infra_config and a_asn:
                a_shared = match_shared_provider(a_asn, "asn", shared_infra_config)
            data["a_record_chain"] = {
                "path": [domain, "A", a_record],
                "web_provider": a_shared[0] if a_shared else None,
                "web_provider_label": a_shared[1] if a_shared else None,
                "web_shared": bool(a_shared),
            }

    stats = compute_stats(domains, fp_matches, clusters)

    # Build infrastructure pivot index
    infra_index = build_infra_index(domains, fp_matches)

    # Build flat fingerprint matches list with enrichment from probed data
    flat_matches = []
    for domain, match_list in fp_matches.items():
        domain_data = domains.get(domain, {})
        tld = _extract_tld(domain)
        registrar = domain_data.get("whois_registrar", "")
        for m in match_list:
            flat_match = dict(m)
            flat_match["domain"] = domain
            flat_match["tld"] = tld
            flat_match["registrar"] = registrar
            flat_matches.append(flat_match)

    # Write output files
    os.makedirs(output_dir, exist_ok=True)

    # --- Sharded domains ---
    # Group domains by first character for shard files
    shards = defaultdict(dict)
    for domain, data in domains.items():
        key = _shard_key(domain)
        shards[key][domain] = data

    shard_manifest = {}
    for key, shard_domains in sorted(shards.items()):
        shard_filename = f"domains_{key}.json"
        shard_path = os.path.join(output_dir, shard_filename)
        with open(shard_path, "w", encoding="utf-8") as f:
            json.dump(shard_domains, f, separators=(",", ":"), ensure_ascii=False)
        shard_manifest[key] = {
            "file": shard_filename,
            "count": len(shard_domains),
        }
        log.info("Wrote %s (%d domains)", shard_path, len(shard_domains))

    # domain_shards.json — manifest of all shard files
    manifest_path = os.path.join(output_dir, "domain_shards.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(shard_manifest, f, indent=2, ensure_ascii=False)
    log.info("Wrote %s (%d shards, %d total domains)",
             manifest_path, len(shard_manifest), len(domains))

    # fingerprint_matches.json — compact separators
    fp_path = os.path.join(output_dir, "fingerprint_matches.json")
    with open(fp_path, "w", encoding="utf-8") as f:
        json.dump(flat_matches, f, separators=(",", ":"), ensure_ascii=False)
    log.info("Wrote %s (%d matches)", fp_path, len(flat_matches))

    # clusters.json — compact separators
    clusters_path = os.path.join(output_dir, "clusters.json")
    with open(clusters_path, "w", encoding="utf-8") as f:
        json.dump(clusters, f, separators=(",", ":"), ensure_ascii=False)
    log.info("Wrote %s (%d nodes, %d edges)", clusters_path,
             len(clusters["nodes"]), len(clusters["edges"]))

    # stats.json — pretty-printed
    stats_path = os.path.join(output_dir, "stats.json")
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    log.info("Wrote %s", stats_path)

    # infra_index.json — pivot search index
    infra_path = os.path.join(output_dir, "infra_index.json")
    with open(infra_path, "w", encoding="utf-8") as f:
        json.dump(infra_index, f, separators=(",", ":"), ensure_ascii=False)
    idx_size = sum(len(v["domains"]) for cat in infra_index.values() for v in cat.values())
    log.info("Wrote %s (%d index entries)", infra_path, idx_size)

    return domains, flat_matches, clusters, stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Build JSON data files for the investigation frontend"
    )
    parser.add_argument(
        "--probed", default=DEFAULT_PROBED,
        help="Path to probed domains CSV (default: %(default)s)"
    )
    parser.add_argument(
        "--fingerprints", default=DEFAULT_FINGERPRINTS,
        help="Path to fingerprint matches CSV (default: %(default)s)"
    )
    parser.add_argument(
        "--output-dir", default=DEFAULT_OUTPUT_DIR,
        help="Output directory for JSON files (default: %(default)s)"
    )
    parser.add_argument(
        "--min-cluster-size", type=int, default=DEFAULT_MIN_CLUSTER_SIZE,
        help="Minimum domains to form a cluster (default: %(default)s)"
    )
    args = parser.parse_args()

    # Check required files
    missing = []
    if not os.path.exists(args.probed):
        missing.append(args.probed)
    if not os.path.exists(args.fingerprints):
        missing.append(args.fingerprints)

    if missing:
        for f in missing:
            log.error("Required file not found: %s", f)
        sys.exit(1)

    # Resolve optional files — use defaults, warn if missing
    opt_files = {}
    for name, config in OPTIONAL_FILES.items():
        if os.path.exists(config["path"]):
            opt_files[name] = config
        else:
            log.warning("Optional file not found (skipping): %s", config["path"])

    build_outputs(
        probed_path=args.probed,
        fingerprints_path=args.fingerprints,
        output_dir=args.output_dir,
        min_cluster_size=args.min_cluster_size,
        optional_files=opt_files,
    )


if __name__ == "__main__":
    main()
