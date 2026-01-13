#!/usr/bin/env python3
"""
fingerprint_kits.py

Proof of Concept: Identify "Phishing Kits" by visually hashing screenshots of domains.
Uses Playwright for headless browsing and ImageHash for perceptual hashing.
"""

import asyncio
import argparse
import sys
from io import BytesIO
from typing import List, Dict

# Check imports
try:
    from playwright.async_api import async_playwright
    import imagehash
    from PIL import Image
except ImportError:
    print("Missing dependencies. Run: pip install -r visual_requirements.txt")
    print("Then install the browser: playwright install chromium")
    sys.exit(1)

async def capture_and_hash(urls: List[str], concurrency: int = 3):
    """
    Visits a list of URLs, takes screenshots, and calculates pHash.
    """
    results = {}
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        # Create a semaphore to limit concurrency
        sem = asyncio.Semaphore(concurrency)

        async def process_url(url):
            async with sem:
                page = await browser.new_page()
                try:
                    print(f"[*] Visiting {url}...")
                    # Go to page, wait for load
                    try:
                        await page.goto(url, timeout=15000, wait_until="domcontentloaded")
                        # Wait a bit for rendering
                        await asyncio.sleep(2)
                    except Exception as e:
                        print(f"[!] Failed to load {url}: {e}")
                        await page.close()
                        return None

                    # Screenshot
                    png_bytes = await page.screenshot(full_page=False)
                    
                    # Convert to PIL Image
                    img = Image.open(BytesIO(png_bytes))
                    
                    # Calculate pHash
                    # hash_size=8 -> 64 bit hash
                    phash = imagehash.phash(img)
                    
                    print(f"[+] Hashed {url}: {phash}")
                    await page.close()
                    return (url, phash, img)
                    
                except Exception as e:
                    print(f"[!] Error processing {url}: {e}")
                    await page.close()
                    return None

        tasks = [process_url(u) for u in urls]
        completed = await asyncio.gather(*tasks)
        
        # Filter failures
        valid_results = [r for r in completed if r is not None]
        return valid_results

def cluster_hashes(data: List[tuple], threshold: int = 5):
    """
    Groups URLs that have visually similar hashes (Hamming distance < threshold).
    """
    clusters = []
    processed = set()

    for i in range(len(data)):
        if i in processed:
            continue
            
        url1, hash1, _ = data[i]
        
        # Start a new cluster
        current_cluster = {
            "leader_hash": hash1,
            "members": [url1]
        }
        processed.add(i)
        
        # Compare against all others
        for j in range(i + 1, len(data)):
            if j in processed:
                continue
                
            url2, hash2, _ = data[j]
            
            # Hamming distance
            dist = hash1 - hash2
            
            if dist <= threshold:
                current_cluster["members"].append(url2)
                processed.add(j)
        
        clusters.append(current_cluster)
        
    return clusters

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--urls", nargs="+", help="List of URLs to test")
    parser.add_argument("--threshold", type=int, default=10, help="Sensitivity (Lower = stricter match)")
    args = parser.parse_args()

    # Default test set if no URLs provided
    if not args.urls:
        print("[*] No URLs provided. using default test set...")
        urls = [
            "https://www.google.com",
            "https://google.com",       # Should match www.google.com visually
            "https://www.bing.com",     # Distinct
            "https://www.example.com",  # Distinct
            "https://example.com"       # Should match
        ]
    else:
        urls = args.urls

    print(f"[*] Starting visual analysis on {len(urls)} URLs...")
    data = await capture_and_hash(urls)
    
    if not data:
        print("[!] No data captured.")
        return

    print("\n[*] Clustering results...")
    clusters = cluster_hashes(data, args.threshold)
    
    print(f"\n{'='*60}")
    print(f"VISUAL FINGERPRINTING REPORT")
    print(f"{'='*60}")
    
    for idx, cluster in enumerate(clusters):
        leader = cluster["leader_hash"]
        members = cluster["members"]
        count = len(members)
        
        print(f"\n[Cluster {idx+1}] Visual Hash: {leader} (Count: {count})")
        for m in members:
            print(f"  - {m}")
            
        if count > 1:
            print(f"  => POTENTIAL KIT DETECTED (Visual Match)")
    
    print(f"\n{'='*60}")

if __name__ == "__main__":
    asyncio.run(main())
