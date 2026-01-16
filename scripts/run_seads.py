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
    
    # Try to download pre-built binary for Windows
    if platform.system() == "Windows":
        try:
            url = f"https://github.com/andpalmier/seads/releases/download/{SEADS_VERSION}/seads_Windows_x86_64.zip"
            logging.info(f"Downloading SEADS from {url}...")
            r = requests.get(url, stream=True)
            if r.status_code == 200:
                with zipfile.ZipFile(BytesIO(r.content)) as z:
                    for filename in z.namelist():
                        if filename.endswith(".exe"):
                            with open(BINARY_NAME, "wb") as f:
                                f.write(z.read(filename))
                            logging.info(f"Downloaded and extracted {BINARY_NAME}")
                            return os.path.abspath(BINARY_NAME)
        except Exception as e:
            logging.error(f"Failed to download binary: {e}")

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

def parse_seads_output(current_keyword=""):
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
        # Header handled in main initialization
            
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
    
    # SEADS Refactor: Run iteratively per keyword to prevent OOM/Hang
    # This allows us to kill the process if a specific keyword hangs (like 'secure' on Yahoo)
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--keywords", help="Comma-separated list of keywords to scan (overrides file)")
    args = parser.parse_args()

    if args.keywords:
        keywords = [k.strip() for k in args.keywords.split(",") if k.strip()]
        logging.info(f"Using manual keywords: {keywords}")
    else:
        all_keywords = load_keywords()
        # Random sample of 10 to prevent OOM/Timeouts on Github Actions
        # In a real full run, you might want all.
        import random
        keywords = random.sample(all_keywords, min(len(all_keywords), 30))
        logging.info(f"Loaded {len(all_keywords)} keywords. Sampling {len(keywords)}: {keywords}")

    logging.info(f"Starting Scan for {len(keywords)} keywords using {seads_bin}...")

    # Initialize output file if it doesn't exist
    if not os.path.exists(OUTPUT_CSV):
        with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['query', 'ad_domain', 'display_url', 'link', 'engine'])
            writer.writeheader()

    for i, keyword in enumerate(keywords):
        logging.info(f"[{i+1}/{len(keywords)}] Scanning for: '{keyword}'")
        
        # Create temp config for just this keyword
        config_data = {
            "queries": [{"query": keyword}],
            "concurrency": 1, # Strict Serial to save RAM
        }
        
        import yaml
        temp_config = f"temp_seads_{i}.yaml"
        with open(temp_config, 'w') as f:
            yaml.dump(config_data, f)
            
        cmd = [
            seads_bin,
            "-config", temp_config,
            "-out", OUTPUT_JSON,  # This will be overwritten each time
            "-screenshot", "",
            "-noredirect"
        ]
        
        try:
            # Enforce 2-minute timeout per keyword
            subprocess.run(cmd, check=False, timeout=120) 
            # Parse immediately and append
            parse_seads_output(keyword)
        except subprocess.TimeoutExpired:
            logging.error(f"Timeout expired for keyword '{keyword}'. Skipping...")
        except Exception as e:
            logging.error(f"Error running seads for '{keyword}': {e}")
        finally:
            if os.path.exists(temp_config):
                os.remove(temp_config)
            # Clean up json output to avoid duplicates
            if os.path.exists(OUTPUT_JSON):
                os.remove(OUTPUT_JSON)

def parse_seads_output(current_keyword=""):
    """Parses JSON and appends to CSV."""
    if not os.path.exists(OUTPUT_JSON):
        return

    findings = []
    try:
        with open(OUTPUT_JSON, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list):
                findings = data
    except Exception as e:
        # JSON might be empty or malformed
        return

    count = 0
    with open(OUTPUT_CSV, 'a', newline='', encoding='utf-8') as f:
        fields = ['query', 'ad_domain', 'display_url', 'link', 'engine']
        writer = csv.DictWriter(f, fieldnames=fields)
        # Header already written in main()
            
        for item in findings:
            row = {
                'query': item.get('Keyword', current_keyword),
                'ad_domain': item.get('Domain', ''),
                'display_url': item.get('DisplayUrl', ''),
                'link': item.get('Link', ''),
                'engine': item.get('Engine', 'unknown')
            }
            if row['ad_domain']:
                writer.writerow(row)
                count += 1
                
    if count > 0:
        logging.info(f"  Found {count} ads for '{current_keyword}'")


if __name__ == "__main__":
    main()
