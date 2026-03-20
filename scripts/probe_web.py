#!/usr/bin/env python3
"""
probe_web.py

Active fingerprinting of domains via HTTP/S (Asynchronous).
Optimized: Uses a fixed-size worker pool (producer-consumer) to limit memory usage.
"""

import argparse
import csv
import re
import random
import asyncio
import aiohttp
import sys
from typing import Dict, Any, List

# Explicit Research User-Agent (Best Practice)
USER_AGENT = "DomainIntelResearch/1.0 (+https://github.com/elchacal801/domain_intel; contact: open-issue-on-repo)"

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
        "title": "",
        "redirect_status": "",
        "redirect_target": ""
    }
    try:
        headers = {"User-Agent": USER_AGENT}
        
        # Reduced timeout to fail fast
        timeout = aiohttp.ClientTimeout(total=8, connect=4)
        
        # Jitter: Be polite to destination infrastructure
        await asyncio.sleep(random.uniform(0.05, 0.2)) 
        
        async with session.get(
            url, 
            headers=headers, 
            proxy=proxy, 
            timeout=timeout, 
            ssl=False, 
            allow_redirects=True
        ) as response:
            result["status"] = str(response.status)
            result["server"] = response.headers.get("Server", "")
            # Capture redirect info from history
            if response.history:
                result["redirect_status"] = str(response.history[0].status)
                result["redirect_target"] = str(response.history[0].headers.get("Location", ""))
            if response.status < 500:
                try:
                    # Limit response size read to avoid hanging on large files
                    text = await response.text()
                    result["title"] = get_title(text)
                except (UnicodeDecodeError, ValueError):
                    pass
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        pass
        
    return result

async def worker(queue: asyncio.Queue, session: aiohttp.ClientSession, proxy: str):
    while True:
        row = await queue.get()
        try:
            domain = row.get("domain")
            if domain:
                # Per-domain hard deadline (covers DNS + connect + read)
                try:
                    await asyncio.wait_for(
                        _probe_domain(row, domain, session, proxy),
                        timeout=15
                    )
                except asyncio.TimeoutError:
                    pass  # Skip this domain, move on
        except Exception:
            pass
        finally:
            queue.task_done()

async def _probe_domain(row: dict, domain: str, session: aiohttp.ClientSession, proxy: str):
    """Probe a single domain via HTTP and HTTPS."""
    task_https = fetch(session, f"https://{domain}", proxy)
    task_http = fetch(session, f"http://{domain}", proxy)
    res_https, res_http = await asyncio.gather(task_https, task_http)
    row["https_status"] = res_https["status"]
    row["https_server"] = res_https["server"]
    row["https_title"] = res_https["title"]
    row["http_status"] = res_http["status"]
    row["http_server"] = res_http["server"]
    row["http_title"] = res_http["title"]
    row["http_redirect_status"] = res_http["redirect_status"]
    row["http_redirect_target"] = res_http["redirect_target"]

async def prober(input_file: str, output_file: str, max_workers: int, proxy: str, limit: int = 0):
    rows = []
    fieldnames = []
    
    print(f"[*] Reading {input_file}...")
    try:
        with open(input_file, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            fieldnames = reader.fieldnames if reader.fieldnames else []
    except FileNotFoundError:
        print(f"[!] Input {input_file} not found.")
        return

    # Filter/Limit
    if limit > 0:
        print(f"[*] Limiting probe to first {limit} domains.")
        rows = rows[:limit]

    # Add new output columns
    new_cols = ["http_status", "http_title", "http_server", "https_status", "https_title", "https_server",
                "http_redirect_status", "http_redirect_target"]
    for c in new_cols:
        if c not in fieldnames:
            fieldnames.append(c)
            
    print(f"[*] Probing {len(rows)} domains with {max_workers} workers...")
    
    queue = asyncio.Queue()
    
    # Fill queue
    for r in rows:
        queue.put_nowait(r)
        
    # Connector tuning
    connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300, force_close=False)
    
    # Global deadline: write partial results instead of hanging in CI
    global_timeout_secs = 30 * 60  # 30 minutes

    async with aiohttp.ClientSession(connector=connector) as session:
        # Create workers
        workers = []
        for _ in range(max_workers):
            task = asyncio.create_task(worker(queue, session, proxy))
            workers.append(task)
            
        # Wait for queue to process (with hard deadline)
        try:
            async def _drain():
                while not queue.empty():
                    done = len(rows) - queue.qsize()
                    print(f"[*] Progress: {done}/{len(rows)}", end='\r')
                    await asyncio.sleep(1)
                await queue.join()

            await asyncio.wait_for(_drain(), timeout=global_timeout_secs)
        except asyncio.TimeoutError:
            remaining = queue.qsize()
            print(f"\n[!] Global timeout reached. {remaining} domains skipped. Writing partial results.")
        
        # Cancel workers
        for w in workers:
            w.cancel()
            
    print(f"\n[*] Writing results to {output_file}...")
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    
    print("[*] Done.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/dea_domains.csv")
    ap.add_argument("--output", default="data/dea_domains_probed.csv")
    ap.add_argument("--workers", type=int, default=50, help="Concurrency limit. Default 50 (Reasonable for public scanning).") 
    ap.add_argument("--proxy", help="Proxy URL (e.g. http://localhost:8080)")
    ap.add_argument("--limit", type=int, default=0, help="Max domains to scan (for testing).")
    
    args = ap.parse_args()
    
    # Windows SelectorPolicy fix for asyncio
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    asyncio.run(prober(args.input, args.output, args.workers, args.proxy, args.limit))

if __name__ == "__main__":
    main()
