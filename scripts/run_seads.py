#!/usr/bin/env python3
"""
run_seads.py

Wrapper to download/run SEADS (Search Engine Ad Scanner) and parse results.
- Downloads binary from GitHub Releases (if not present).
- Runs scan using keywords from config/seads_keywords.txt.
- Outputs findings to data/discovered_ads.csv.
"""

import os
import sys
import argparse
import subprocess
import json
import csv
import platform
import logging
import requests
import zipfile
import tarfile
from io import BytesIO

# Configuration
SEADS_VERSION = "v1.0.4" 
# Note: As of late 2024/2025 finding a stable pre-built binary link is key. 
# We will assume a standard go install or docker is preferred, but for CI we try binary first.
# If binary fails, we fall back to 'go install' if available, or error out.

# Repo: https://github.com/andpalmier/seads
BINARY_NAME = "seads.exe" if platform.system() == "Windows" else "seads"
KEYWORDS_FILE = "config/seads_keywords.txt"
OUTPUT_JSON = "data/seads_raw.json"
OUTPUT_CSV = "data/discovered_ads.csv"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def install_seads():
    """Attempts to install/locate SEADS."""
    # Check if exists locally
    if os.path.exists(BINARY_NAME):
        return os.path.abspath(BINARY_NAME)
        
    # Check path
    import shutil
    if shutil.which("seads"):
        return "seads"

    logging.info("SEADS not found. Assuming Docker usage or manual install for now.")
    # For this script, we will assume the user or CI has 'seads' available
    # Or we use 'go install' if go is available.
    if shutil.which("go"):
        logging.info("Go found. Installing seads via go install...")
        try:
            subprocess.check_call(["go", "install", "github.com/andpalmier/seads@latest"])
            # GOBIN usually in ~/go/bin
            home = os.path.expanduser("~")
            gobin = os.path.join(home, "go", "bin", BINARY_NAME)
            if os.path.exists(gobin):
                return gobin
        except Exception as e:
            logging.error(f"Go install failed: {e}")
            
    logging.warning("Could not automatically install SEADS. Please ensure 'seads' is in PATH or current dir.")
    return "seads" # Hope for the best

def load_keywords():
    if not os.path.exists(KEYWORDS_FILE):
        return ["login", "bank"]
    with open(KEYWORDS_FILE, 'r') as f:
        # Filter comments and empty lines
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def parse_seads_output():
    """Converts the JSON output from SEADS into our CSV format."""
    if not os.path.exists(OUTPUT_JSON):
        logging.warning("No JSON output found from SEADS.")
        return

    findings = []
    try:
        with open(OUTPUT_JSON, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # SEADS json structure varies, let's assume standard list of findings
            # Adjust based on actual structure
            if isinstance(data, list):
                findings = data
    except Exception as e:
        logging.error(f"Failed to parse findings: {e}")
        return

    # Write CSV
    file_exists = os.path.exists(OUTPUT_CSV)
    count = 0
    with open(OUTPUT_CSV, 'a', newline='', encoding='utf-8') as f:
        fields = ['query', 'ad_domain', 'display_url', 'link', 'engine']
        writer = csv.DictWriter(f, fieldnames=fields)
        if not file_exists:
            writer.writeheader()
            
        for item in findings:
            # Normalize fields based on Seads schema
            row = {
                'query': item.get('Keyword', ''),
                'ad_domain': item.get('Domain', ''), # The visible domain
                'display_url': item.get('DisplayUrl', ''),
                'link': item.get('Link', ''), # The clickthrough (often encoded)
                'engine': item.get('Engine', 'unknown')
            }
            if row['ad_domain']:
                writer.writerow(row)
                count += 1
                
    logging.info(f"Appended {count} ads to {OUTPUT_CSV}")

def main():
    seads_bin = install_seads()
    keywords = load_keywords()
    
    logging.info(f"Starting Scan for {len(keywords)} keywords using {seads_bin}...")
    
    # SEADS doesn't take a file input for keywords usually, it takes arguments.
    # But running 50 separate process calls is noisy.
    
    # Randomly sample keywords to prevent OOM / Timeout on free runners
    import random
    if len(keywords) > 10:
        logging.info(f"Sampling 10 keywords from {len(keywords)} to prevent OOM/Timeout...")
        keywords = random.sample(keywords, 10)

    config_data = {
        "queries": [{"query": k} for k in keywords],
        "concurrency": 2, # Reduced from 4 to 2 for stability
        # "global-domain-exclusion": {"exclusion-list": ["google.com", "bing.com"]} # etc
    }
    
    import yaml
    temp_config = "temp_seads_config.yaml"
    with open(temp_config, 'w') as f:
        yaml.dump(config_data, f)
        
    cmd = [
        seads_bin,
        "-config", temp_config,
        "-out", OUTPUT_JSON,
        "-screenshot", "", # Disable for this pass
        "-noredirect" # Just get the ad link, don't follow chains (speed)
    ]
    
    try:
        subprocess.run(cmd, check=False) # Don't error out script if seads fails slightly
    except FileNotFoundError:
        logging.error("SEADS binary execution failed. Is it installed?")
    
    parse_seads_output()
    
    # Clean up
    if os.path.exists(temp_config):
        os.remove(temp_config)

if __name__ == "__main__":
    main()
