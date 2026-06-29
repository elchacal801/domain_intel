#!/usr/bin/env python3
"""
split_data.py

Splits a CSV file into N chunks for parallel processing.
Usage: python split_data.py --input data.csv --chunks 10 --output-prefix data_part
"""

import argparse
import csv
import os
import math

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Input CSV file")
    parser.add_argument("--chunks", type=int, default=10, help="Number of chunks")
    parser.add_argument("--output-prefix", required=True, help="Output file prefix (e.g. data/dea_part)")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] Input file {args.input} not found.")
        return

    # Read all rows
    print(f"[*] Reading {args.input}...")
    with open(args.input, "r", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            print("[!] Empty file.")
            return
        
        rows = list(reader)

    total_rows = len(rows)
    chunk_size = math.ceil(total_rows / args.chunks)
    print(f"[*] Total rows: {total_rows}. Split into {args.chunks} chunks of ~{chunk_size} rows.")

    for i in range(args.chunks):
        start = i * chunk_size
        end = start + chunk_size
        chunk_rows = rows[start:end]
        
        if not chunk_rows:
            break

        out_name = f"{args.output_prefix}_{i}.csv"
        print(f"  -> Writing {out_name} ({len(chunk_rows)} rows)")
        
        with open(out_name, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(chunk_rows)

    print("[*] Done.")

if __name__ == "__main__":
    main()
