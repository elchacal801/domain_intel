#!/usr/bin/env python3
"""
merge_results.py

Merges multiple CSV shards into a single file.
Assumes all shards have the same header.
Usage: python merge_results.py --pattern "data/result_part_*.csv" --output data/result_final.csv
"""

import argparse
import csv
import glob
import os

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pattern", required=True, help="Glob pattern for input files")
    parser.add_argument("--output", required=True, help="Output merged CSV file")
    args = parser.parse_args()

    files = sorted(glob.glob(args.pattern))
    if not files:
        print(f"[!] No files found matching {args.pattern}")
        return

    print(f"[*] Found {len(files)} files to merge.")

    header = None
    total_rows = 0

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
                        total_rows += 1

            except Exception as e:
                print(f"\n[!] Error reading {file_path}: {e}")

    print(f"\n[*] Merged {total_rows} rows into {args.output}")

if __name__ == "__main__":
    main()
