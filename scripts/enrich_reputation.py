#!/usr/bin/env python3
"""
enrich_reputation.py

Adds reputation and age data to domains.
1. Checks DNS RBLs (Spamhaus ZEN, etc.) - simple boolean "listed" check.
2. Queries RDAP for 'creation date' to determine domain age.

Input: CSV with 'domain'
Output: CSV with 'is_rbl_listed', 'creation_date', 'domain_age_days'
Optimized: Higher concurrency with ThreadPoolExecutor map.
"""

import argparse
import logging
import os
import csv
import dns.resolver
import dns.exception
import requests
import time
import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional
from tqdm import tqdm
from shared.sanitize import sanitize_csv_value

logger = logging.getLogger(__name__)

# Generic RBLs to check (careful with rate limits on public resolvers)
RBLS = [
    "zen.spamhaus.org",
    "bl.spamcop.net" 
]

# OTX Setup
OTX_API_KEY = os.environ.get("ALIENVAULT_OTX_API_KEY")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{}/general"
# Simple in-memory cache to avoid redundant hits in same run (though input shouldn't have dupes)
OTX_CACHE = {} 

def check_otx(domain: str) -> str:
    """Queries AlienVault OTX for pulses."""
    if not OTX_API_KEY:
        return ""
        
    url = OTX_BASE_URL.format(domain)
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    
    try:
        # Rate limit prevention (naive)
        # OTX is 10k/hour = ~2.7/sec. 50 workers will HAMMER this.
        # We need to rely on the requests failing or implement a global ratelimiter.
        # For now, we swallow errors to avoid stopping the pipeline.
        resp = requests.get(url, headers=headers, timeout=5)
        
        if resp.status_code == 200:
            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            count = pulse_info.get("count", 0)
            if count > 0:
                # Get Pulse names if possible?
                pulses = pulse_info.get("pulses", [])
                names = [p.get("name", "Unknown") for p in pulses[:3]] # Top 3
                return f"OTX_Pulses:{count};" + ",".join(names)
        elif resp.status_code == 429:
            # Rate Limit
            return "OTX_RateLimited"
            
    except requests.RequestException:
        pass
        
    return ""


def check_rbl(domain: str, resolver) -> List[str]:
    """Returns list of RBLs the domain (or its IP) is listed in."""
    hits = []
    # 1. Domain Block List (DBL) check
    try:
        q = f"{domain}.dbl.spamhaus.org"
        resolver.resolve(q, 'A')
        hits.append("spamhaus_dbl")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.resolver.Timeout, dns.exception.DNSException):
        pass
    return hits

def _extract_org_from_vcard(vcard_array) -> str:
    """Extract organization name from a jCard (RFC 7095) vcardArray.

    Prefers the ``org`` property over ``fn`` since ``fn`` is often a
    person's formatted name rather than the organisation.

    Args:
        vcard_array: The ``vcardArray`` value from an RDAP entity, e.g.
            ``["vcard", [["version", {}, "text", "4.0"], ["fn", ...]]]``.

    Returns:
        The extracted organisation string, or ``""`` if none found.
    """
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return ""

    properties = vcard_array[1]
    if not isinstance(properties, list):
        return ""

    org_val = ""
    fn_val = ""
    for prop in properties:
        if not isinstance(prop, list) or len(prop) < 4:
            continue
        name = prop[0]
        value = prop[3]
        # value can be a string or (for org) sometimes a list
        if isinstance(value, list):
            value = value[0] if value else ""
        if not isinstance(value, str) or not value.strip():
            continue
        if name == "org":
            org_val = value.strip()
        elif name == "fn":
            fn_val = value.strip()

    # Prefer org; fall back to fn
    return org_val or fn_val


def _extract_registrant_org(data: dict) -> str:
    """Walk an RDAP response and return the registrant organisation.

    The function tries multiple strategies in priority order:

    1. Top-level entity with ``"registrant"`` role -- parse its vCard.
    2. Nested entities (entity inside another entity) with
       ``"registrant"`` role -- parse their vCard.
    3. Entity ``handle``, ``name``, or ``publicIds`` fields on the
       registrant entity when vCard parsing yields nothing.

    Returns:
        The registrant organisation string, or ``""`` if not found.
    """

    def _org_from_entity(entity: dict) -> str:
        """Try to get org from a single entity dict."""
        # Strategy A: vCard
        vcard_array = entity.get("vcardArray")
        org = _extract_org_from_vcard(vcard_array)
        if org:
            return org

        # Strategy B: handle / name fields (some registries use these)
        for field in ("name", "handle"):
            val = entity.get(field)
            if isinstance(val, str) and val.strip():
                return val.strip()

        # Strategy C: publicIds
        for pid in entity.get("publicIds", []):
            ident = pid.get("identifier")
            if isinstance(ident, str) and ident.strip():
                return ident.strip()

        return ""

    # Pass 1: top-level entities with registrant role
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrant" in roles:
            org = _org_from_entity(entity)
            if org:
                return org

    # Pass 2: nested entities (one level deep -- covers registrant
    # nested under the registrar entity, which some TLDs do)
    for entity in data.get("entities", []):
        for sub in entity.get("entities", []):
            roles = sub.get("roles", [])
            if "registrant" in roles:
                org = _org_from_entity(sub)
                if org:
                    return org

    return ""


def _extract_creation_date(data: dict):
    """Extract the domain creation date from RDAP events.

    Prefers the ``registration`` event; falls back to ``last changed``
    if no registration event is present.

    Returns:
        A ``(creation_date_str, age_days_str)`` tuple, or ``("", "")``
        if no usable event is found.
    """
    events = data.get("events", [])
    registration_date = None
    last_changed_date = None

    for e in events:
        action = e.get("eventAction")
        date_str = e.get("eventDate")
        if not date_str:
            continue
        if action == "registration":
            registration_date = date_str
        elif action == "last changed" and last_changed_date is None:
            last_changed_date = date_str

    c_date = registration_date or last_changed_date
    if not c_date:
        return ("", "")

    try:
        dt = datetime.datetime.strptime(c_date.split("T")[0], "%Y-%m-%d")
        creation_str = dt.strftime("%Y-%m-%d")
        delta = datetime.datetime.now(datetime.timezone.utc) - dt.replace(tzinfo=datetime.timezone.utc)
        return (creation_str, str(delta.days))
    except (ValueError, IndexError):
        return ("", "")


# RDAP bootstrap URL.  rdap.org acts as a redirect service that routes
# to the authoritative RDAP server for each TLD.
RDAP_BASE_URL = "https://rdap.org/domain/{}"
RDAP_TIMEOUT = 10  # seconds -- RDAP redirects can be slow


def get_rdap_data(domain: str) -> Dict[str, str]:
    """
    Queries RDAP for creation date and registrant organization.
    Returns {'creation_date': 'YYYY-MM-DD', 'age_days': '123', 'registrant_org': '...'}
    """
    res = {"creation_date": "", "age_days": "", "registrant_org": ""}
    try:
        url = RDAP_BASE_URL.format(domain)
        r = requests.get(url, timeout=RDAP_TIMEOUT)
        if r.status_code != 200:
            logger.debug("RDAP HTTP %s for %s", r.status_code, domain)
            return res

        data = r.json()

        # --- Creation date / age ---
        creation_date, age_days = _extract_creation_date(data)
        res["creation_date"] = creation_date
        res["age_days"] = age_days

        # --- Registrant organisation ---
        org = _extract_registrant_org(data)
        if org:
            res["registrant_org"] = sanitize_csv_value(org)

    except requests.Timeout:
        logger.debug("RDAP timeout for %s", domain)
    except requests.ConnectionError:
        logger.debug("RDAP connection error for %s", domain)
    except requests.RequestException as exc:
        logger.debug("RDAP request error for %s: %s", domain, exc)
    except (ValueError, KeyError) as exc:
        logger.debug("RDAP parse error for %s: %s", domain, exc)

    return res

def process_one(row: Dict) -> Dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    
    domain = row.get("domain", "")
    if not domain:
        return row
        
    # RBL
    hits = check_rbl(domain, resolver)
    row["rbl_hits"] = ";".join(hits)
    
    # RDAP
    # We might want to limit RDAP to only 'suspicious' ones to save API calls
    # or just do all if list is small. 
    rdap = get_rdap_data(domain)
    row["creation_date"] = rdap["creation_date"]
    row["age_days"] = rdap["age_days"]
    row["registrant_org"] = rdap.get("registrant_org", "")
    
    # OTX Check (if key exists)
    otx_tags = check_otx(domain)
    if otx_tags:
        row["otx_risk"] = sanitize_csv_value(otx_tags)

    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/dea_domains_enriched.csv")
    ap.add_argument("--output", default="data/dea_domains_reputation.csv")
    ap.add_argument("--workers", type=int, default=50) 
    args = ap.parse_args()
    
    rows = []
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            fieldnames = reader.fieldnames if reader.fieldnames else []
    except FileNotFoundError:
        print("[!] Input file not found.")
        return
            
    # Add new headers
    new_cols = ["rbl_hits", "creation_date", "age_days", "otx_risk", "registrant_org"]
    for c in new_cols:
        if c not in fieldnames:
            fieldnames.append(c)
    
    print(f"[*] Processing {len(rows)} domains for reputation/age with {args.workers} workers...")
    
    results = []
    # Use map instead of submitting futures to a list to save memory
    with ThreadPoolExecutor(max_workers=args.workers) as exe:
        # map is lazy-ish, but for lists it might consume. 
        # However, it yields results in order, which is nice.
        # We wrap in list() to consume all, or iterate.
        iterator = exe.map(process_one, rows)
        
        # Wrap with tqdm for progress
        for res in tqdm(iterator, total=len(rows)):
            results.append(res)
            
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
        
    print(f"[*] Done. Saved to {args.output}")

if __name__ == "__main__":
    main()
