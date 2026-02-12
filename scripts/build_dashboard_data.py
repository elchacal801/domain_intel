#!/usr/bin/env python3
"""
build_dashboard_data.py

Generates a pre-computed dashboard summary (dashboard_summary.json) from
the enriched pipeline output. This gives the frontend a single compact
JSON file for KPI display without needing to parse large CSVs client-side.

Run after generate_pivots.py and track_history.py in the CI pipeline.

Output: data/dashboard_summary.json
"""

import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path("data")
OUTPUT = DATA_DIR / "dashboard_summary.json"


def count_csv_rows(filepath):
    """Count data rows (excluding header) in a CSV file."""
    if not filepath.exists():
        return 0
    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.reader(f)
        next(reader, None)  # skip header
        return sum(1 for _ in reader)


def read_csv_column_sum(filepath, col_index=1):
    """Sum integer values from a specific column."""
    if not filepath.exists():
        return 0
    total = 0
    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            try:
                total += int(row[col_index])
            except (IndexError, ValueError):
                pass
    return total


def get_history_latest():
    """Read the latest entry from history.json if it exists."""
    history_file = DATA_DIR / "history.json"
    if not history_file.exists():
        return {}
    try:
        with open(history_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data:
            return data[-1]
    except (json.JSONDecodeError, KeyError):
        pass
    return {}


def get_campaign_stats():
    """Compute campaign hunt summary stats."""
    campaign_file = DATA_DIR / "campaign_hunt_history.csv"
    if not campaign_file.exists():
        return {"total_ips": 0, "countries": 0, "queries_used": 0}

    ips = set()
    countries = set()
    queries = set()

    with open(campaign_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("ip"):
                ips.add(row["ip"])
            if row.get("country"):
                countries.add(row["country"])
            if row.get("query"):
                queries.add(row["query"])

    return {
        "total_ips": len(ips),
        "countries": len(countries),
        "queries_used": len(queries),
    }


def build_file_inventory():
    """List all dashboard data files with sizes."""
    dashboard_files = [
        "asn_counts.csv",
        "mx_counts.csv",
        "web_server_counts.csv",
        "risk_counts.csv",
        "http_status_counts.csv",
        "title_keyword_counts.csv",
        "openclaw_exposed.csv",
        "ai_classifications.csv",
        "shodan_intelligence.csv",
        "campaign_hunt_history.csv",
        "daily_briefing.json",
        "history.json",
        "visual_clusters.json",
    ]

    inventory = {}
    for name in dashboard_files:
        path = DATA_DIR / name
        if path.exists():
            stat = path.stat()
            inventory[name] = {
                "size_kb": round(stat.st_size / 1024, 1),
                "rows": count_csv_rows(path) if name.endswith(".csv") else None,
            }

    return inventory


def main():
    print("[*] Building dashboard summary...")

    history = get_history_latest()
    campaign = get_campaign_stats()
    inventory = build_file_inventory()

    # Count high-risk entries
    risk_total = read_csv_column_sum(DATA_DIR / "risk_counts.csv")

    # Openclaw stats
    openclaw_count = count_csv_rows(DATA_DIR / "openclaw_exposed.csv")

    summary = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "kpis": {
            "total_domains": history.get("total", 0),
            "live_threats": history.get("live", 0),
            "high_risk_signals": risk_total,
            "openclaw_exposed": openclaw_count,
            "campaign_ips": campaign["total_ips"],
        },
        "campaign": campaign,
        "file_inventory": inventory,
        "data_files_count": len(inventory),
    }

    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"[*] Dashboard summary written to {OUTPUT}")
    print(f"    Domains: {summary['kpis']['total_domains']:,}")
    print(f"    Live threats: {summary['kpis']['live_threats']:,}")
    print(f"    Risk signals: {summary['kpis']['high_risk_signals']:,}")
    print(f"    OpenClaw: {summary['kpis']['openclaw_exposed']}")
    print(f"    Campaign IPs: {summary['kpis']['campaign_ips']}")
    print(f"    Data files: {summary['data_files_count']}")


if __name__ == "__main__":
    main()
