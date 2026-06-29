#!/usr/bin/env python3
"""
generate_fp_registry.py

Generates frontend/src/data/fpRegistry.js from config/fingerprints/*.yaml.
Eliminates manual sync between YAML fingerprint definitions and frontend metadata.

Usage:
    python scripts/generate_fp_registry.py
    python scripts/generate_fp_registry.py --fingerprint-dir config/fingerprints
                                           --output frontend/src/data/fpRegistry.js
"""

import argparse
import glob
import json
import os
import sys

import yaml


DEFAULT_FP_DIR = "config/fingerprints"
DEFAULT_OUTPUT = "frontend/src/data/fpRegistry.js"


def load_fingerprints(fingerprint_dir):
    """Load all YAML fingerprint definitions from a directory."""
    registry = {}
    for fp_file in sorted(glob.glob(os.path.join(fingerprint_dir, "*.yaml"))):
        with open(fp_file, "r", encoding="utf-8") as f:
            fp = yaml.safe_load(f)
        if not fp or "id" not in fp:
            continue
        registry[fp["id"]] = {
            "name": fp.get("name", fp["id"]),
            "description": fp.get("description", "").strip(),
            "flame_tp_ids": fp.get("flame_tp_ids", []),
        }
    return registry


def generate_js(registry):
    """Generate the fpRegistry.js content as a string."""
    lines = [
        "/**",
        " * Auto-generated from config/fingerprints/*.yaml",
        " * Do not edit manually — run: python scripts/generate_fp_registry.py",
        " */",
        "",
        f"export const fpRegistry = {json.dumps(registry, indent=4)};",
        "",
        "// --- Static registries (maintained manually) ---",
        "",
        "export const tpRegistry = {",
        "    'TP-0001': 'Brand impersonation typosquat — single-character deviation from major brands',",
        "    'TP-0002': 'Insurance/healthcare brand typosquat cluster targeting Aetna and similar',",
        "    'TP-0003': 'Bulk DEA hosting infrastructure on OVH using disposable MX',",
        "    'TP-0005': 'Allstate brand typosquat cluster with character substitution',",
        "    'TP-0010': 'GName registrar bulk registration with Cloudflare, China nexus',",
        "    'TP-0012': 'Character-substitution typosquat targeting tier-1 brands (Google, Amazon)',",
        "    'TP-0013': 'Adobe brand typosquat cluster with suffix/prefix manipulation',",
        "    'TP-0015': 'High-confidence typosquat evidence cluster for financial/enterprise brands (BMO, Adobe)',",
        "    'TP-0017': 'Numeric domain cluster on .xyz TLD — suspected automated registration',",
        "    'TP-0019': 'Prefix-manipulation typosquat cluster targeting insurance brands',",
        "};",
        "",
        "/** Column header tooltips */",
        "export const columnTooltips = {",
        "    domain: 'Fully qualified domain name being investigated',",
        "    fp_id: 'Infrastructure fingerprint ID — a pattern of shared hosting, registrar, or DNS indicators',",
        "    confidence: 'Match confidence score (0-100%). Higher = stronger evidence the domain matches the fingerprint pattern',",
        "    flame_tp_ids: 'FLAME Threat Path IDs — structured threat intelligence tracking identifiers',",
        "    tld: 'Top-level domain extension (e.g. .com, .xyz, .info)',",
        "    registrar: 'Domain registrar organization (from WHOIS/RDAP)',",
        "};",
        "",
        "/** KPI tooltips */",
        "export const kpiTooltips = {",
        "    total_domains: 'Total number of domains monitored in the pipeline, including all sources',",
        "    matched_domains: 'Domains matching at least one infrastructure fingerprint pattern',",
        "    unique_fingerprints: 'Number of distinct fingerprint patterns that matched at least one domain',",
        "    total_clusters: 'Infrastructure clusters where ≥3 domains share MX, IP, or registrar+NS',",
        "};",
        "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate fpRegistry.js from YAML fingerprint definitions"
    )
    parser.add_argument(
        "--fingerprint-dir", default=DEFAULT_FP_DIR,
        help="Directory containing fingerprint YAML files (default: %(default)s)"
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help="Output JS file path (default: %(default)s)"
    )
    args = parser.parse_args()

    if not os.path.isdir(args.fingerprint_dir):
        print(f"[!] Fingerprint directory not found: {args.fingerprint_dir}")
        sys.exit(1)

    registry = load_fingerprints(args.fingerprint_dir)
    js_content = generate_js(registry)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(js_content)

    print(f"[*] Generated {args.output} with {len(registry)} fingerprints")


if __name__ == "__main__":
    main()
