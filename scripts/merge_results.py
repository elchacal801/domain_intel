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

    with open(args.output, "w", newline="", encoding="utf-8") as out_f:
        writer = csv.writer(out_f)
        
        for file_path in files:
            print(f"  Processing {file_path}...", end="\r")
            try:
                with open(file_path, "r", encoding="utf-8-sig") as in_f:
                    reader = csv.reader(in_f)
                    try:
                        current_header = next(reader)
                    except StopIteration:
                        continue # Empty file

                    if header is None:
                        header = current_header
                        writer.writerow(header)
                    elif current_header != header:
                        print(f"\n[!] Warning: Header mismatch in {file_path}. Skipping file.")
                        continue

                    # Write remaining rows
                    rows = list(reader)
                    if rows:
                        writer.writerows(rows)
                        total_rows += len(rows)

            except Exception as e:
                print(f"\n[!] Error reading {file_path}: {e}")

    print(f"\n[*] Merged {total_rows} rows into {args.output}")

if __name__ == "__main__":
    main()
