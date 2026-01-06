#!/usr/bin/env python3
"""
probe_web.py

Active fingerprinting of domains via HTTP/S (Asynchronous).
- Random User-Agents
- Follows redirects (limit)
- Captures Status, Title, Server
- High concurrency with asyncio/aiohttp

Usage:
  python probe_web.py --input data/dea_domains.csv --output data/dea_domains_probed.csv --workers 500
"""

import argparse
import csv
import re
import random
import asyncio
import aiohttp
import sys
from typing import Dict, Any

# Suppress insecure request warnings if they pop up (less relevant in aiohttp but good practice)
# In aiohttp, we handle verification via ssl context or verify_ssl=False

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

def get_title(html: str) -> str:
    if not html: return ""
    # Simple regex title extraction
    m = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()[:100] # Limit length
    return ""

async def fetch(session: aiohttp.ClientSession, url: str, proxy: str = None) -> Dict[str, str]:
    result = {
        "status": "",
        "server": "",
        "title": ""
    }
    try:
        # random UA for each request
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        
        async with session.get(
            url, 
            headers=headers, 
            proxy=proxy, 
            timeout=aiohttp.ClientTimeout(total=5, connect=3), 
            ssl=False, 
            allow_redirects=True
        ) as response:
            result["status"] = str(response.status)
            result["server"] = response.headers.get("Server", "")
            # Only read text if status is OK-ish to save bandwidth, or just read it.
            # Reading body can be slow, so limit valid text reading
            if response.status < 500:
                try:
                    text = await response.text(errors='ignore')
                    result["title"] = get_title(text)
                except:
                    pass
    except Exception:
        # Timeout or connection error
        pass
        
    return result

async def probe_domain(sem: asyncio.Semaphore, session: aiohttp.ClientSession, row: Dict[str, Any], proxy: str = None) -> Dict[str, Any]:
    domain = row.get("domain")
    if not domain:
        return row
        
    async with sem:
        # Launch HTTP and HTTPS in parallel or sequential? 
        # Parallel is faster but heavier. Let's do sequential to be polite(r) or parallel if we want raw speed.
        # Given 220k domains, we want speed. Parallel.
        
        task_https = fetch(session, f"https://{domain}", proxy)
        task_http = fetch(session, f"http://{domain}", proxy)
        
        res_https, res_http = await asyncio.gather(task_https, task_http)
        
        row["https_status"] = res_https["status"]
        row["https_server"] = res_https["server"]
        row["https_title"] = res_https["title"]
        
        row["http_status"] = res_http["status"]
        row["http_server"] = res_http["server"]
        row["http_title"] = res_http["title"]
        
    return row

async def prober(input_file: str, output_file: str, max_workers: int, proxy: str):
    rows = []
    fieldnames = []
    
    try:
        with open(input_file, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            fieldnames = reader.fieldnames if reader.fieldnames else []
    except FileNotFoundError:
        print(f"[!] Input {input_file} not found.")
        return

    # Add new output columns
    new_cols = ["http_status", "http_title", "http_server", "https_status", "https_title", "https_server"]
    for c in new_cols:
        if c not in fieldnames:
            fieldnames.append(c)
            
    print(f"[*] Probing {len(rows)} domains with {max_workers} concurrent workers...")
    
    sem = asyncio.Semaphore(max_workers)
    
    # Connector tuning
    connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for row in rows:
            task = asyncio.create_task(probe_domain(sem, session, row, proxy))
            tasks.append(task)
            
        # Use simple counter or tqdm if available, but for now simple print
        results = []
        completed = 0
        total = len(tasks)
        
        # Gather with basic progress
        for coro in asyncio.as_completed(tasks):
            res = await coro
            results.append(res)
            completed += 1
            if completed % 1000 == 0:
                print(f"[*] Progress: {completed}/{total}", end='\r')
                
    print(f"\n[*] Writing results to {output_file}...")
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    print("[*] Done.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/dea_domains.csv")
    ap.add_argument("--output", default="data/dea_domains_probed.csv")
    ap.add_argument("--workers", type=int, default=100)
    ap.add_argument("--proxy", help="Proxy URL (e.g. http://localhost:8080)")
    
    args = ap.parse_args()
    
    # Windows SelectorPolicy fix for asyncio
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    asyncio.run(prober(args.input, args.output, args.workers, args.proxy))

if __name__ == "__main__":
    main()
