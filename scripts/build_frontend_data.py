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
import json
import logging
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

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
        "fields": ["ports", "vulns"],
        "prefix": "shodan_",
    },
    "phishtank_matches": {
        "path": "data/phishtank_matches.csv",
        "fields": ["phishtank_url", "urlhaus_threat"],
        "prefix": "phishtank_",
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
# Cluster computation
# ---------------------------------------------------------------------------

def compute_clusters(domains, min_cluster_size=DEFAULT_MIN_CLUSTER_SIZE):
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

    nodes = {}  # id -> node dict (dedup)
    edges = []

    def add_infra_node(node_id, node_type, label, domain_count):
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "label": label,
                "size": min(5 + domain_count, 30),
            }

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
            add_infra_node(infra_id, "mx_host", mx_host, len(domain_set))
            for d in domain_set:
                dom_id = add_domain_node(d)
                edges.append({"source": dom_id, "target": infra_id})

    # Process IP clusters
    for ip, domain_set in ip_groups.items():
        if len(domain_set) >= min_cluster_size:
            infra_id = f"ip:{ip}"
            add_infra_node(infra_id, "ip", ip, len(domain_set))
            for d in domain_set:
                dom_id = add_domain_node(d)
                edges.append({"source": dom_id, "target": infra_id})

    # Process registrar+NS clusters
    for (reg, ns), domain_set in regns_groups.items():
        if len(domain_set) >= min_cluster_size:
            infra_id = f"regns:{reg}|{ns}"
            label = f"{reg} / {ns}"
            add_infra_node(infra_id, "registrar_ns", label, len(domain_set))
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

    return {
        "total_domains": len(domains),
        "matched_domains": len(fp_matches),
        "total_clusters": total_clusters,
        "unique_fingerprints": len(all_fp_ids),
        "tld_distribution": dict(tld_counter.most_common(20)),
        "top_fingerprints": dict(fp_counter.most_common(10)),
        "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


# ---------------------------------------------------------------------------
# Output building
# ---------------------------------------------------------------------------

def build_outputs(probed_path, fingerprints_path, output_dir,
                  min_cluster_size=DEFAULT_MIN_CLUSTER_SIZE,
                  optional_files=None):
    """
    Main orchestrator: load data, compute derived structures, write JSON files.

    Parameters:
        probed_path: path to dea_domains_probed.csv
        fingerprints_path: path to fingerprint_matches.csv
        output_dir: directory for JSON output files
        min_cluster_size: minimum domains to form a cluster
        optional_files: dict of optional file configs to merge
    """
    if optional_files is None:
        optional_files = {}

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

    # Compute derived structures
    clusters = compute_clusters(domains, min_cluster_size=min_cluster_size)
    stats = compute_stats(domains, fp_matches, clusters)

    # Build flat fingerprint matches list with enrichment from probed data
    flat_matches = []
    for domain, match_list in fp_matches.items():
        domain_data = domains.get(domain, {})
        tld = _extract_tld(domain)
        registrar = domain_data.get("registrant_org", "")
        for m in match_list:
            flat_match = dict(m)
            flat_match["domain"] = domain
            flat_match["tld"] = tld
            flat_match["registrar"] = registrar
            flat_matches.append(flat_match)

    # Write output files
    os.makedirs(output_dir, exist_ok=True)

    # domains.json — compact separators
    domains_path = os.path.join(output_dir, "domains.json")
    with open(domains_path, "w", encoding="utf-8") as f:
        json.dump(domains, f, separators=(",", ":"), ensure_ascii=False)
    log.info("Wrote %s (%d domains)", domains_path, len(domains))

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
