#!/usr/bin/env python3
"""
build_investigate_index.py

Generates a compact JSON search index from dea_domains_probed.csv
for the frontend Investigate tab. Runs during CI after merge_results.py.

Strategy:
  - Read the full probed CSV (268K+ rows)
  - Select only columns needed for search/display/filter
  - Use short single-letter keys to reduce file size
  - Output as JSON array (gzip-friendly, browser-parseable)
  - Optionally output a metadata sidecar with filter facets

Output:
  docs/data/investigate_index.json   (~4-8 MB, ~1-2 MB gzipped)
  docs/data/investigate_meta.json    (facet counts for dropdowns)

Size Budget:
  268K rows × ~120 bytes/row = ~32 MB raw JSON
  With short keys: ~18 MB raw → ~3 MB gzipped
  GitHub Pages serves gzip automatically via CDN.
"""

import argparse
import csv
import json
import os
import sys
from collections import Counter
from datetime import datetime

INPUT_FILE = "data/dea_domains_probed.csv"
OUTPUT_INDEX = "docs/data/investigate_index.json"
OUTPUT_META = "docs/data/investigate_meta.json"

# Column mapping: CSV header -> short key
# Short keys reduce JSON size by ~40% vs full names
COLUMN_MAP = {
    "domain":        "d",   # domain name (required)
    "primary_mx":    "mx",  # mail exchanger
    "mx_ip":         "mi",  # MX IP address
    "asn":           "a",   # ASN number
    "asn_name":      "an",  # ASN org name
    "cc":            "c",   # country code
    "bgp_prefix":    "bp",  # BGP prefix
    "nameservers":   "ns",  # nameservers
    "risk_tags":     "rt",  # risk tags
    "rbl_hits":      "rb",  # RBL listings
    "creation_date": "cd",  # domain creation date
    "age_days":      "ag",  # domain age in days
    "otx_risk":      "ox",  # OTX pulse data
    "http_status":   "hs",  # HTTP status code
    "http_title":    "ht",  # HTTP page title
    "http_server":   "hv",  # HTTP server header
    "https_status":  "ss",  # HTTPS status code
    "https_title":   "st",  # HTTPS page title
    "https_server":  "sv",  # HTTPS server header
}

# Reverse map for metadata
KEY_LABELS = {v: k for k, v in COLUMN_MAP.items()}


def compute_risk_level(row):
    """
    Matches the frontend getRiskLevel() logic.
    Returns: 'critical', 'high', 'medium', 'low', or 'none'
    """
    rt = row.get("risk_tags", "")
    rb = row.get("rbl_hits", "")
    ox = row.get("otx_risk", "")

    if not rt and not rb and not ox:
        return "none"
    if "FraudScore" in rt or "spamhaus" in rb:
        return "critical"
    if "HighRisk" in rt:
        return "high"
    if ox:
        return "medium"
    return "low"


def build_index(input_file, limit=0):
    """
    Reads CSV and builds compact index rows.
    Returns (rows, metadata).
    """
    rows = []
    country_counts = Counter()
    asn_counts = Counter()
    risk_counts = Counter()
    server_counts = Counter()
    status_counts = {"live": 0, "dead": 0, "blocked": 0, "other": 0}

    print(f"[*] Reading {input_file}...")

    if not os.path.exists(input_file):
        print(f"[!] File not found: {input_file}")
        sys.exit(1)

    with open(input_file, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            print("[!] Empty CSV or missing headers.")
            sys.exit(1)

        # Verify expected columns exist
        missing = [col for col in COLUMN_MAP.keys() if col not in reader.fieldnames]
        if missing:
            print(f"[!] Warning: Missing columns: {missing}")
            print(f"    Available: {reader.fieldnames}")

        count = 0
        for row in reader:
            # Build compact row with short keys, skip empty values
            compact = {}
            has_data = False

            for csv_col, short_key in COLUMN_MAP.items():
                val = row.get(csv_col, "").strip()
                if val:
                    # Truncate very long values to save space
                    if short_key in ("ht", "st"):  # titles
                        val = val[:150]
                    elif short_key == "ox":  # OTX - just keep pulse count
                        val = val[:100]
                    elif short_key == "ns":  # nameservers
                        val = val[:120]

                    compact[short_key] = val
                    has_data = True

            # Always include domain even if no other data
            domain = row.get("domain", "").strip()
            if not domain:
                continue

            compact["d"] = domain

            # Pre-compute risk level for faster frontend filtering
            risk = compute_risk_level(row)
            if risk != "none":
                compact["rl"] = risk  # risk_level

            rows.append(compact)

            # Aggregate metadata for filter facets
            cc = row.get("cc", "").strip()
            if cc:
                country_counts[cc] += 1

            an = row.get("asn_name", "").strip()
            if an:
                asn_counts[an] += 1

            risk_counts[risk] += 1

            srv = row.get("http_server", "").strip() or row.get("https_server", "").strip()
            if srv:
                server_counts[srv.split("/")[0].split(" ")[0]] += 1

            # Status classification
            hs = row.get("http_status", "").strip()
            hss = row.get("https_status", "").strip()
            if hs == "200" or hss == "200":
                status_counts["live"] += 1
            elif hs in ("401", "403") or hss in ("401", "403"):
                status_counts["blocked"] += 1
            elif not hs and not hss:
                status_counts["dead"] += 1
            else:
                status_counts["other"] += 1

            count += 1
            if count % 50000 == 0:
                print(f"    Processed {count:,} rows...")

            if limit > 0 and count >= limit:
                print(f"[*] Reached limit of {limit} rows.")
                break

    print(f"[*] Total rows indexed: {len(rows):,}")

    # Build metadata
    meta = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_rows": len(rows),
        "column_map": COLUMN_MAP,
        "facets": {
            "countries": dict(country_counts.most_common(50)),
            "asns": dict(asn_counts.most_common(50)),
            "risk_levels": dict(risk_counts),
            "servers": dict(server_counts.most_common(30)),
            "status": status_counts,
        },
    }

    return rows, meta


def write_output(rows, meta, output_index, output_meta):
    """Writes JSON files to disk."""
    os.makedirs(os.path.dirname(output_index), exist_ok=True)

    print(f"[*] Writing index to {output_index}...")
    with open(output_index, "w", encoding="utf-8") as f:
        # Use separators to minimize whitespace (saves ~30% file size)
        json.dump(rows, f, separators=(",", ":"), ensure_ascii=False)

    size_mb = os.path.getsize(output_index) / (1024 * 1024)
    print(f"    Index size: {size_mb:.1f} MB")

    print(f"[*] Writing metadata to {output_meta}...")
    with open(output_meta, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    print("[*] Done.")


def main():
    parser = argparse.ArgumentParser(
        description="Build investigate search index from probed CSV"
    )
    parser.add_argument(
        "--input", default=INPUT_FILE, help="Input CSV file path"
    )
    parser.add_argument(
        "--output-index", default=OUTPUT_INDEX, help="Output JSON index path"
    )
    parser.add_argument(
        "--output-meta", default=OUTPUT_META, help="Output metadata JSON path"
    )
    parser.add_argument(
        "--limit", type=int, default=0, help="Max rows to index (0 = all)"
    )
    args = parser.parse_args()

    rows, meta = build_index(args.input, args.limit)
    write_output(rows, meta, args.output_index, args.output_meta)


if __name__ == "__main__":
    main()
