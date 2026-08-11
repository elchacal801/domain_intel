#!/usr/bin/env python3
"""
merge_results.py

Merges multiple CSV shards into a single file.
Assumes all shards have the same header.
Usage: python merge_results.py --pattern "data/result_part_*.csv" --output data/result_final.csv

With --expect-input, the merged output's domain set is reconciled against the
given input CSV and the merge exits non-zero on any mismatch — a run that lost
domains must fail loudly, not report success.
"""

import argparse
import csv
import glob
import os
import sys


def _read_domain_set(path: str) -> set:
    """Read the set of domains from a CSV with a 'domain' column (or a plain list)."""
    domains = set()
    with open(path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames and "domain" in reader.fieldnames:
            for row in reader:
                if row.get("domain"):
                    domains.add(row["domain"])
        else:
            f.seek(0)
            for line in f:
                d = line.strip()
                if d and not d.startswith("#") and d.lower() != "domain":
                    domains.add(d)
    return domains


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pattern", required=True, help="Glob pattern for input files")
    parser.add_argument("--output", required=True, help="Output merged CSV file")
    parser.add_argument("--expect-input", default=None,
                        help="CSV of expected domains; after merging, assert the output "
                             "domain set equals this set and exit 1 otherwise.")
    args = parser.parse_args()

    files = sorted(glob.glob(args.pattern))
    if not files:
        print(f"[!] No files found matching {args.pattern}")
        sys.exit(1)

    print(f"[*] Found {len(files)} files to merge.")

    header = None
    total_rows = 0
    merged_domains = set()
    failed_files = []

    # Columns that should be present in merged output for schema consistency
    REQUIRED_COLUMNS = ["flame_tp_ids"]

    with open(args.output, "w", newline="", encoding="utf-8") as out_f:
        writer = None

        for file_path in files:
            print(f"  Processing {file_path}...", end="\r")
            try:
                with open(file_path, "r", encoding="utf-8-sig") as in_f:
                    reader = csv.DictReader(in_f)
                    if not reader.fieldnames:
                        continue  # Empty file

                    current_header = list(reader.fieldnames)

                    if header is None:
                        header = current_header[:]
                        # Ensure required columns are present
                        for col in REQUIRED_COLUMNS:
                            if col not in header:
                                header.append(col)
                        writer = csv.DictWriter(out_f, fieldnames=header)
                        writer.writeheader()

                    # Write remaining rows, filling missing columns with empty string
                    for row in reader:
                        out_row = {col: row.get(col, "") for col in header}
                        writer.writerow(out_row)
                        merged_domains.add(row.get("domain", ""))
                        total_rows += 1

            except Exception as e:
                # A shard that cannot be read means lost domains — never continue silently.
                print(f"\n[!] Error reading {file_path}: {e}")
                failed_files.append(file_path)

    print(f"\n[*] Merged {total_rows} rows into {args.output}")

    if failed_files:
        print(f"[!] {len(failed_files)} shard file(s) failed to read: {failed_files}")
        sys.exit(1)

    if args.expect_input:
        expected = _read_domain_set(args.expect_input)
        missing = sorted(expected - merged_domains)
        extra = sorted(merged_domains - expected)
        if missing or extra:
            if missing:
                print(f"[RECONCILE] FAIL: {len(missing)} expected domains missing from "
                      f"merged output. Sample: {missing[:10]}")
            if extra:
                print(f"[RECONCILE] FAIL: {len(extra)} unexpected domains in merged "
                      f"output. Sample: {extra[:10]}")
            sys.exit(1)
        print(f"[RECONCILE] OK: merged output covers all {len(expected)} expected domains exactly.")
        print(f"[SUMMARY] shards={len(files)} rows={total_rows} expected={len(expected)} "
              f"missing=0 extra=0")


if __name__ == "__main__":
    main()
