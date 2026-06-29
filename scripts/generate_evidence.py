#!/usr/bin/env python3
"""
generate_evidence.py

Generates FLAME-compatible evidence packages from domain_intel
investigation data. Evidence packages are markdown snippets ready
for insertion into FLAME threat path files.

Workflow:
  1. Reads ai_classifications.csv for flame_tp_ids mappings
  2. Reads investigation_*.md files for cluster context
  3. Aggregates cluster data (domains per IP, provider, country)
  4. Generates one markdown file per evidence entry in data/evidence_packages/
  5. Optionally checks flame-evidence-index.json for duplicates

Usage:
    python scripts/generate_evidence.py [--min-domains 10] [--dry-run] [--check-duplicates]
"""

import argparse
import csv
import json
import logging
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
)
log = logging.getLogger("generate_evidence")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CLASSIFICATION_FILE = DATA_DIR / "ai_classifications.csv"
PROBED_FILE = DATA_DIR / "dea_domains_probed.csv"
EVIDENCE_DIR = DATA_DIR / "evidence_packages"

FLAME_EVIDENCE_URL = (
    "https://elchacal801.github.io/flame-fraud/database/flame-evidence-index.json"
)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def load_classifications() -> list[dict]:
    """Load ai_classifications.csv and return rows with flame_tp_ids."""
    results = []
    if not CLASSIFICATION_FILE.exists():
        log.warning("Classification file not found: %s", CLASSIFICATION_FILE)
        return results

    with open(CLASSIFICATION_FILE, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tp_ids = row.get("flame_tp_ids", "").strip()
            if tp_ids:
                results.append(row)
    log.info("Loaded %d classified domains with FLAME TP IDs", len(results))
    return results


def load_probed_domains() -> list[dict]:
    """Load dea_domains_probed.csv for enrichment data (IP, ASN, etc.)."""
    results = []
    if not PROBED_FILE.exists():
        log.warning("Probed file not found: %s", PROBED_FILE)
        return results

    with open(PROBED_FILE, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append(row)
    return results


def load_investigations() -> list[dict]:
    """Load investigation markdown files and extract cluster metadata."""
    investigations = []
    for md_file in sorted(DATA_DIR.glob("investigation_*.md")):
        text = md_file.read_text(encoding="utf-8", errors="replace")
        investigations.append({
            "filename": md_file.name,
            "content": text,
        })
    log.info("Loaded %d investigation files", len(investigations))
    return investigations


def fetch_existing_evidence() -> set[str]:
    """Fetch flame-evidence-index.json and return set of existing evidence IDs."""
    if requests is None:
        log.warning("requests not installed; skipping duplicate check")
        return set()

    try:
        resp = requests.get(FLAME_EVIDENCE_URL, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            ids = {entry.get("evidence_id", "") for entry in data}
            log.info("Fetched %d existing evidence IDs from FLAME", len(ids))
            return ids
        else:
            log.warning("FLAME evidence index returned %d", resp.status_code)
    except Exception as exc:
        log.warning("Failed to fetch evidence index: %s", exc)
    return set()


# ---------------------------------------------------------------------------
# Cluster aggregation
# ---------------------------------------------------------------------------


def aggregate_clusters(
    classifications: list[dict],
    probed: list[dict],
) -> dict[str, dict]:
    """Group domains by resolved IP to identify clusters.

    Returns dict keyed by IP with domain count, TP distribution,
    key indicators, and representative domains.
    """
    # Build IP -> enrichment lookup from probed data
    domain_ip = {}
    for row in probed:
        domain = row.get("domain", "").strip()
        ip = row.get("resolved_ip", row.get("ip", "")).strip()
        if domain and ip:
            domain_ip[domain] = {
                "ip": ip,
                "asn": row.get("asn", ""),
                "provider": row.get("org", row.get("asn_org", "")),
                "country": row.get("country", ""),
            }

    clusters: dict[str, dict] = defaultdict(lambda: {
        "ip": "",
        "domains": [],
        "tp_ids": Counter(),
        "providers": Counter(),
        "countries": Counter(),
        "key_domains": [],
    })

    for row in classifications:
        domain = row.get("domain", "").strip()
        tp_ids_str = row.get("flame_tp_ids", "").strip()

        enrichment = domain_ip.get(domain, {})
        ip = enrichment.get("ip", "unknown")
        if not ip or ip == "unknown":
            continue

        cluster = clusters[ip]
        cluster["ip"] = ip
        cluster["domains"].append(domain)

        for tp_id in tp_ids_str.split(","):
            tp_id = tp_id.strip()
            if tp_id:
                cluster["tp_ids"][tp_id] += 1

        if enrichment.get("provider"):
            cluster["providers"][enrichment["provider"]] += 1
        if enrichment.get("country"):
            cluster["countries"][enrichment["country"]] += 1

    # Identify key domains (non-generic, notable names)
    for ip, cluster in clusters.items():
        # Take up to 5 shortest domain names as "key" indicators
        sorted_domains = sorted(cluster["domains"], key=len)
        cluster["key_domains"] = sorted_domains[:5]

    log.info("Aggregated %d clusters from %d classified domains",
             len(clusters), len(classifications))
    return dict(clusters)


# ---------------------------------------------------------------------------
# Evidence package generation
# ---------------------------------------------------------------------------


def generate_evidence_id(tp_id: str, year: int, existing_ids: set[str]) -> str:
    """Generate a stable evidence ID: EV-TPXXXX-YYYY-NNN."""
    # Normalize TP ID: TP-0003 -> TP0003
    tp_clean = tp_id.replace("-", "")
    for seq in range(1, 1000):
        ev_id = f"EV-{tp_clean}-{year}-{seq:03d}"
        if ev_id not in existing_ids:
            return ev_id
    raise ValueError(f"Exhausted evidence IDs for {tp_id}/{year}")


def cluster_to_evidence_package(
    cluster: dict,
    tp_id: str,
    evidence_id: str,
    date_str: str,
) -> str:
    """Format a cluster as a FLAME evidence markdown snippet."""
    ip = cluster["ip"]
    domain_count = len(cluster["domains"])
    provider = cluster["providers"].most_common(1)[0][0] if cluster["providers"] else "Unknown"
    country = cluster["countries"].most_common(1)[0][0] if cluster["countries"] else "Unknown"
    key_domains = ", ".join(cluster["key_domains"])
    confidence = "High" if domain_count >= 50 else "Medium" if domain_count >= 10 else "Low"

    # Determine CFPF phase coverage based on TP
    # Default: P1, P2 for infrastructure-type evidence
    phases = "P1, P2"

    title_parts = []
    if provider != "Unknown":
        title_parts.append(provider)
    title_parts.append(f"{domain_count} Domain Cluster")
    title = " ".join(title_parts)

    summary = (
        f"Cluster of {domain_count} domains hosted on {ip} ({provider}, {country}) "
        f"with FLAME TP mapping to {tp_id}. "
        f"Key domains include: {key_domains}."
    )

    return f"""### {evidence_id}: {title}
- **Source**: domain_intel investigation {date_str}
- **Cluster**: {ip} ({provider}, {country})
- **Domain Count**: {domain_count} domains
- **Key Indicators**: {key_domains}
- **CFPF Phase Coverage**: {phases}
- **Confidence**: {confidence}
- **Summary**: {summary}
"""


def generate_packages(
    clusters: dict[str, dict],
    existing_ids: set[str],
    min_domains: int,
    dry_run: bool,
) -> list[dict]:
    """Generate evidence packages for qualifying clusters.

    Returns list of generated evidence metadata dicts.
    """
    date_str = datetime.now().strftime("%Y-%m-%d")
    year = datetime.now().year
    generated = []

    # Track all IDs we generate to avoid self-collision
    all_ids = set(existing_ids)

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    for ip, cluster in sorted(clusters.items(), key=lambda x: len(x[1]["domains"]), reverse=True):
        domain_count = len(cluster["domains"])

        if domain_count < min_domains:
            log.debug("Skipping %s: %d domains < %d minimum", ip, domain_count, min_domains)
            continue

        # Generate one package per TP mapping
        for tp_id, count in cluster["tp_ids"].most_common():
            evidence_id = generate_evidence_id(tp_id, year, all_ids)
            all_ids.add(evidence_id)

            if evidence_id in existing_ids:
                log.info("Skipping duplicate: %s", evidence_id)
                continue

            package_md = cluster_to_evidence_package(
                cluster, tp_id, evidence_id, date_str
            )

            meta = {
                "evidence_id": evidence_id,
                "tp_id": tp_id,
                "cluster_ip": ip,
                "domain_count": domain_count,
                "date": date_str,
            }

            if dry_run:
                log.info("[DRY RUN] Would generate: %s (IP=%s, %d domains, %s)",
                         evidence_id, ip, domain_count, tp_id)
                print(f"\n--- {evidence_id} ---")
                print(package_md)
            else:
                out_path = EVIDENCE_DIR / f"{evidence_id}.md"
                out_path.write_text(package_md, encoding="utf-8")
                log.info("Generated: %s -> %s", evidence_id, out_path)

            generated.append(meta)

    return generated


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Generate FLAME evidence packages from domain_intel data"
    )
    parser.add_argument(
        "--min-domains", type=int, default=10,
        help="Minimum domains per cluster to qualify (default: 10)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview packages without writing files"
    )
    parser.add_argument(
        "--check-duplicates", action="store_true",
        help="Fetch flame-evidence-index.json to check for duplicates"
    )
    args = parser.parse_args()

    log.info("FLAME Evidence Package Generator")
    log.info("Data directory: %s", DATA_DIR)

    # Load data
    classifications = load_classifications()
    probed = load_probed_domains()
    investigations = load_investigations()

    if not classifications:
        log.warning("No classified domains with FLAME TP IDs found. "
                     "Run ai_classify_web.py first.")
        sys.exit(0)

    # Check for duplicates
    existing_ids: set[str] = set()
    if args.check_duplicates:
        existing_ids = fetch_existing_evidence()

    # Aggregate into clusters
    clusters = aggregate_clusters(classifications, probed)

    # Generate packages
    generated = generate_packages(
        clusters, existing_ids, args.min_domains, args.dry_run
    )

    # Summary
    log.info("---")
    log.info("Generated %d evidence packages (min_domains=%d, dry_run=%s)",
             len(generated), args.min_domains, args.dry_run)

    if generated and not args.dry_run:
        log.info("Packages written to: %s", EVIDENCE_DIR)
        log.info("Next: Review packages, then copy evidence sections to FLAME threat paths")


if __name__ == "__main__":
    main()
