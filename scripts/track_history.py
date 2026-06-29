#!/usr/bin/env python3
"""
track_history.py

Calculates daily statistics for the domain intelligence dataset.
metrics: Total Domains, Live Domains (Active Web/Mail), Dead Domains.

Outputs:
1. data/history.csv (Appended daily for archival)
2. docs/history.json (Overwritten daily for dashboard visualization)
"""

import csv
import json
import os
import datetime

# Files
INPUT_FILE = "data/dea_domains_probed.csv"
CSV_OUTPUT = "data/history.csv"
JSON_OUTPUT = "docs/history.json"

def calculate_stats():
    total = 0
    live = 0
    
    if not os.path.exists(INPUT_FILE):
        print(f"[!] Input file not found: {INPUT_FILE}")
        return None

    # Criteria for "Live": HTTP 200/403/etc OR MX Records present
    # Using pandas would be slower for just counting, but robust.
    # Let's use standard CSV for speed and zero-dep (if possible, but we have pandas in env likely)
    # Sticking to standard CSV to keep it lightweight.
    
    try:
        with open(INPUT_FILE, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                total += 1
                
                # Check Liveness
                is_live = False
                
                # 1. HTTP Status (any numeric status implies the server responded)
                http_status = row.get("http_status", "").strip()
                https_status = row.get("https_status", "").strip()
                if (http_status and http_status.isdigit()) or (https_status and https_status.isdigit()):
                    is_live = True
                
                # 2. MX Records
                if not is_live and row.get("mx_records"):
                    is_live = True
                    
                if is_live:
                    live += 1
                    
    except Exception as e:
        print(f"[!] Error reading CSV: {e}")
        return None

    return {
        "date": datetime.date.today().isoformat(),
        "total": total,
        "live": live,
        "dead": total - live
    }

def update_csv(stats):
    file_exists = os.path.exists(CSV_OUTPUT)
    
    # Check if today is already written to avoid duplicates
    if file_exists:
        with open(CSV_OUTPUT, "r", encoding="utf-8") as f:
            lines = f.readlines()
            if lines and stats["date"] in lines[-1]:
                print(f"[*] Stats for {stats['date']} already exist. Skipping CSV append.")
                return

    with open(CSV_OUTPUT, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["date", "total", "live", "dead"])
        if not file_exists:
            writer.writeheader()
        writer.writerow(stats)
    print(f"[*] Appended to {CSV_OUTPUT}")

def update_json():
    # Read full CSV to generate JSON
    data = []
    if os.path.exists(CSV_OUTPUT):
        with open(CSV_OUTPUT, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Cast numbers
                row["total"] = int(row["total"])
                row["live"] = int(row["live"])
                row["dead"] = int(row["dead"])
                data.append(row)
    
    # Write JSON for frontend
    os.makedirs(os.path.dirname(JSON_OUTPUT), exist_ok=True)
    with open(JSON_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[*] Updated {JSON_OUTPUT}")

def main():
    print("[-] Calculating Domain Stats...")
    stats = calculate_stats()
    if stats:
        print(f"    Total: {stats['total']}")
        print(f"    Live:  {stats['live']}")
        update_csv(stats)
        update_json()
    else:
        print("[!] Failed to calculate stats.")

if __name__ == "__main__":
    main()
