#!/usr/bin/env python3
"""
visual_fingerprint.py

Production script for Visual Phishing Kit Clustering.
1. Reads domains from data/dea_domains_probed.csv (or AI results).
2. Filters for high-risk targets (e.g. valid HTTP response, suspicious keywords).
3. Uses Playwright to capture screenshots.
4. Uses ImageHash to cluster visually similar pages.
5. Outputs data/visual_clusters.json
"""

import asyncio
import argparse
import sys
import os
import csv
import json
import logging
from io import BytesIO
from typing import List, Dict, Tuple
from datetime import datetime

# Dependencies
try:
    from playwright.async_api import async_playwright
    import imagehash
    from PIL import Image
except ImportError:
    print("Missing dependencies.")
    sys.exit(1)

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

INPUT_FILE = "data/dea_domains_probed.csv"
OUTPUT_CLUSTERS = "data/visual_clusters.json"
OUTPUT_HASHES = "data/visual_hashes.csv"

# Configuration
MAX_DOMAINS_TO_SCAN = 200 # Limit for prototype/production safety
CONCURRENCY = 5

def get_targets(limit: int) -> List[str]:
    """
    Selects high-priority domains to screenshot.
    Priority:
    1. AI Classified as Phishing/C2 (if available) - TODO: Merge logic
    2. Domains with titles containing 'login', 'account', 'secure', 'update'
    3. Random sample of others
    """
    candidates = []
    
    if not os.path.exists(INPUT_FILE):
        return []

    with open(INPUT_FILE, 'r', encoding='utf-8-sig', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get('domain')
            title = row.get('title', '').lower()
            status = row.get('status_code', '')
            
            # Only alive domains
            if status != '200':
                continue

            # Heuristic: Interesting titles
            keywords = ['login', 'account', 'verify', 'update', 'secure', 'banking', 'wallet']
            weight = 0
            if any(k in title for k in keywords):
                weight = 10
            
            candidates.append((domain, weight))
    
    # Sort by weight desc
    candidates.sort(key=lambda x: x[1], reverse=True)
    
    # Return top N
    return [c[0] for c in candidates[:limit]]

async def capture_and_hash(domains: List[str], concurrency: int) -> List[dict]:
    results = []
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(user_agent="DomainIntelResearch/1.0 (Visual)")
        
        sem = asyncio.Semaphore(concurrency)

        async def process(domain):
            url = f"http://{domain}" # Try HTTP first
            async with sem:
                page = await context.new_page()
                try:
                    logging.info(f"Screenshotting {domain}...")
                    try:
                        await page.goto(url, timeout=10000, wait_until="domcontentloaded")
                        await asyncio.sleep(1) # Render
                    except:
                        # Try HTTPS
                        try:
                            url = f"https://{domain}"
                            await page.goto(url, timeout=10000, wait_until="domcontentloaded")
                            await asyncio.sleep(1)
                        except:
                            return None

                    # Screenshot (JPEG for smaller size)
                    # We capture as PNG in memory for hashing (better precision), but save as JPEG for web display
                    png_bytes = await page.screenshot(full_page=False)
                    img = Image.open(BytesIO(png_bytes))

                    # Save to disk for dashboard (Convert to JPEG)
                    screenshot_path = f"data/screenshots/{domain}.jpg"
                    os.makedirs("data/screenshots", exist_ok=True)
                    
                    rgb_im = img.convert('RGB')
                    rgb_im.save(screenshot_path, format='JPEG', quality=70, optimize=True)
                    
                    # Hash
                    phash = str(imagehash.phash(img))
                    
                    await page.close()
                    return {"domain": domain, "url": url, "phash": phash}
                    
                except Exception as e:
                    logging.error(f"Error {domain}: {e}")
                    await page.close()
                    return None

        tasks = [process(d) for d in domains]
        completed = await asyncio.gather(*tasks)
        results = [r for r in completed if r]
        await browser.close()
        
    return results

def cluster_results(results: List[dict], threshold: int = 5) -> List[dict]:
    # Group by hash similarity
    # Simple naive clustering
    clusters = []
    processed = set()
    
    # Convert hex hash string to imagehash object for comparison
    for r in results:
        r['obj_hash'] = imagehash.hex_to_hash(r['phash'])

    for i in range(len(results)):
        if i in processed:
            continue
            
        leader = results[i]
        members = [leader['domain']]
        processed.add(i)
        
        for j in range(i + 1, len(results)):
            if j in processed:
                continue
            
            candidate = results[j]
            dist = leader['obj_hash'] - candidate['obj_hash']
            
            if dist <= threshold:
                members.append(candidate['domain'])
                processed.add(j)
        
        if len(members) > 0:
            clusters.append({
                "visual_hash": leader['phash'],
                "count": len(members),
                "domains": members,
                "example_url": leader['url']
            })
            
    # Remove hash objects before jumping to json
    for c in clusters:
        c.sort(key=lambda x: x['count'], reverse=True)
        
    return clusters

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=MAX_DOMAINS_TO_SCAN)
    args = parser.parse_args()
    
    logging.info("Selecting targets...")
    targets = get_targets(args.limit)
    logging.info(f"Targeting {len(targets)} domains for visual analysis.")
    
    if not targets:
        logging.warning("No targets found.")
        # Create empty artifacts to satisfy pipeline
        with open(OUTPUT_CLUSTERS, 'w') as f: json.dump([], f)
        with open(OUTPUT_HASHES, 'w') as f: f.write("domain,phash\n")
        return

    logging.info("Capturing screenshots...")
    data = await capture_and_hash(targets, CONCURRENCY)
    
    logging.info("Clustering...")
    clusters = cluster_results(data)
    
    # Filter for interesting clusters (size > 1) or save all?
    # Saving all for now
    
    # Save Clusters JSON
    with open(OUTPUT_CLUSTERS, 'w', encoding='utf-8') as f:
        json.dump(clusters, f, indent=2)
        
    # Save Flat CSV
    with open(OUTPUT_HASHES, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "phash"])
        for r in data:
            writer.writerow([r['domain'], r['phash']])

    logging.info(f"Done. Saved {len(data)} hashes and {len(clusters)} clusters.")

if __name__ == "__main__":
    asyncio.run(main())
