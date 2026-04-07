#!/usr/bin/env python3
"""
merge_lists_v3b.py

Builds three domain lists:
  1) dea_domains.csv        -> strict disposable/burner provider domains (deduped)
  2) high_abuse_domains.csv -> domains from "abuse-oriented" feeds (opt-in)
  3) dea_allowlist.csv      -> known false positives to exclude from DEA

Discovery artifacts (dnstwist, SEADS, CT logs, manual candidates) are written to
a SEPARATE file (discovery_domains.csv) with source provenance. They are NOT merged
into the DEA list. The CI workflow concatenates both files into a unified pipeline
input (pipeline_input.csv) for enrichment.

Default behavior:
- Builds DEA from community disposable-email lists only
- Fetches and APPLIES allowlist subtraction (--no-filter-allowlist to disable)
- Discovery artifacts → discovery_domains.csv (separate output)
- Does NOT include StopForumSpam unless --include-stopforumspam is set

Usage:
  python merge_lists_v3b.py
  python merge_lists_v3b.py --include-stopforumspam
  python merge_lists_v3b.py --no-filter-allowlist   # disable allowlist subtraction
"""

import argparse
import csv
import logging
import os
import requests
import json
import re
import time
from typing import Callable, Dict, Iterable, List, Set, Tuple
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

DEFAULT_TIMEOUT = 25

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,63}$"
)

UA = {"User-Agent": "unum-dea-merge/3b"}


def log(msg: str) -> None:
    print(msg, flush=True)


def fetch(url: str, timeout: int) -> str:
    req = Request(url, headers=UA)
    with urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def normalize_domain(s: str) -> str:
    s = (s or "").strip().lower()
    s = s.strip('"').strip("'").strip()
    s = s.replace("mailto:", "")
    s = s.lstrip("@")
    s = s.rstrip(".")
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0]
    if "@" in s:
        s = s.split("@")[-1]
    s = s.lstrip("*.")  # wildcard
    return s


def is_valid_domain(d: str) -> bool:
    if not d or len(d) > 253:
        return False
    return bool(DOMAIN_RE.match(d))


def parse_line_list(text: str) -> Set[str]:
    out: Set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith("//") or line.startswith(";"):
            continue
        # strip inline comments
        line = line.split("#", 1)[0].strip()
        line = line.split("//", 1)[0].strip()
        line = line.split(";", 1)[0].strip()
        d = normalize_domain(line)
        if is_valid_domain(d):
            out.add(d)
    return out


def parse_json_domains(text: str) -> Set[str]:
    out: Set[str] = set()
    obj = json.loads(text)
    if isinstance(obj, list):
        items = obj
    elif isinstance(obj, dict):
        items = obj.get("domains") or obj.get("data") or obj.get("items") or []
    else:
        items = []
    for item in items:
        d = normalize_domain(str(item))
        if is_valid_domain(d):
            out.add(d)
    return out


def parse_tempemail_mx_csv(text: str) -> Set[str]:
    out: Set[str] = set()
    reader = csv.DictReader(text.splitlines())
    if not reader.fieldnames:
        return out

    domain_col = None
    for c in reader.fieldnames:
        if c.lower() in ("domain", "emaildomain", "email_domain"):
            domain_col = c
            break
    if domain_col is None:
        domain_col = reader.fieldnames[0]

    for row in reader:
        d = normalize_domain(row.get(domain_col, ""))
        if is_valid_domain(d):
            out.add(d)
    return out


def safe_fetch_parse(name: str, url: str, parser: Callable[[str], Set[str]], timeout: int) -> Tuple[Set[str], str | None]:
    try:
        t0 = time.time()
        text = fetch(url, timeout)
        doms = parser(text)
        dt = time.time() - t0
        log(f"  [+] {name:28s} {len(doms):7d} domains  ({dt:0.1f}s)")
        return doms, None
    except (HTTPError, URLError, TimeoutError) as e:
        err = f"{type(e).__name__}: {e}"
        log(f"  [!] {name:28s} FAILED  ({err})")
        return set(), err
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        log(f"  [!] {name:28s} FAILED  ({err})")
        return set(), err


def write_csv(domains: Set[str], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain"])
        for d in sorted(domains):
            w.writerow([d])


def write_csv_with_source(domains_by_source: Dict[str, Set[str]], path: str) -> None:
    """Write domains with source_type provenance column."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "source_type"])
        all_rows = []
        for source_type, doms in domains_by_source.items():
            for d in doms:
                all_rows.append((d, source_type))
        # Sort by domain for deterministic output
        all_rows.sort(key=lambda x: x[0])
        for row in all_rows:
            w.writerow(row)


def load_targets(targets_file: str) -> Set[str]:
    """Load target brand domains to exclude from discovery output."""
    targets = set()
    if os.path.exists(targets_file):
        with open(targets_file, "r", encoding="utf-8") as f:
            for line in f:
                d = normalize_domain(line.strip())
                if is_valid_domain(d):
                    targets.add(d)
    return targets


def collect_discovery_domains(targets: Set[str]) -> Dict[str, Set[str]]:
    """
    Collect discovery artifacts into a dict keyed by source type.
    Excludes original target domains (the brands we're protecting).
    These are NOT disposable email providers — they are investigative leads.
    """
    discovery: Dict[str, Set[str]] = {}

    # 1. Dnstwist typosquats (EXCLUDE *original entries — those are the real brands)
    twist_file = "data/potential_typosquats.csv"
    if os.path.exists(twist_file):
        try:
            typosquats = set()
            with open(twist_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    fuzzer = row.get("fuzzer", "").strip()
                    d = normalize_domain(row.get("domain", ""))
                    # Skip the *original entries — these are the actual target brands
                    if fuzzer == "*original":
                        continue
                    # Also skip if this domain is one of our target brands
                    if d in targets:
                        continue
                    if is_valid_domain(d):
                        typosquats.add(d)
            if typosquats:
                log(f"  [+] {'dnstwist_typosquats':28s} {len(typosquats):7d} domains  (local, originals excluded)")
                discovery["typosquat"] = typosquats
        except Exception as e:
            log(f"  [!] Failed to read {twist_file}: {e}")

    # 2. SEADS malvertising discoveries
    seads_file = "data/discovered_ads.csv"
    if os.path.exists(seads_file):
        try:
            seads = set()
            with open(seads_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    d = normalize_domain(row.get("ad_domain", ""))
                    if d in targets:
                        continue
                    if is_valid_domain(d):
                        seads.add(d)
            if seads:
                log(f"  [+] {'seads_malvertising':28s} {len(seads):7d} domains  (local, targets excluded)")
                discovery["malvertising"] = seads
        except Exception as e:
            log(f"  [!] Failed to read {seads_file}: {e}")

    # 3. CT log discoveries
    ct_file = "data/discovered_certs.csv"
    if os.path.exists(ct_file):
        try:
            ct_doms = set()
            with open(ct_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                if reader.fieldnames and "domain" in reader.fieldnames:
                    for row in reader:
                        d = normalize_domain(row.get("domain", ""))
                        if d in targets:
                            continue
                        if is_valid_domain(d):
                            ct_doms.add(d)
            if ct_doms:
                log(f"  [+] {'ct_log_discovery':28s} {len(ct_doms):7d} domains  (local, targets excluded)")
                discovery["ct_discovery"] = ct_doms
        except Exception as e:
            log(f"  [!] Failed to read {ct_file}: {e}")

    # 4. Manual investigation candidates
    manual_file = "data/manual_candidates.csv"
    if os.path.exists(manual_file):
        try:
            manual = set()
            with open(manual_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                col = "domain"
                if reader.fieldnames and col in reader.fieldnames:
                    for row in reader:
                        d = normalize_domain(row.get(col, ""))
                        if d in targets:
                            continue
                        if is_valid_domain(d):
                            manual.add(d)
            if manual:
                log(f"  [+] {'manual_candidates':28s} {len(manual):7d} domains  (local, targets excluded)")
                discovery["investigation"] = manual
        except Exception as e:
            log(f"  [!] Failed to read {manual_file}: {e}")

    # 5. Campaign pivot discoveries (Shodan hunt -> OTX passive DNS)
    pivot_file = "data/campaign_pivot_findings.csv"
    if os.path.exists(pivot_file):
        try:
            pivots = set()
            with open(pivot_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    d = normalize_domain(row.get("discovered_domain", ""))
                    if d in targets:
                        continue
                    if is_valid_domain(d):
                        pivots.add(d)
            if pivots:
                log(f"  [+] {'campaign_pivot':28s} {len(pivots):7d} domains  (local, targets excluded)")
                discovery["campaign_pivot"] = pivots
        except Exception as e:
            log(f"  [!] Failed to read {pivot_file}: {e}")

    # 6. OTX passive DNS pivot results (manual pivot_otx.py runs)
    otx_file = "data/pivot_otx_results.csv"
    if os.path.exists(otx_file):
        try:
            otx_pivots = set()
            with open(otx_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    d = normalize_domain(row.get("discovered_domain", ""))
                    if d in targets:
                        continue
                    if is_valid_domain(d):
                        otx_pivots.add(d)
            if otx_pivots:
                log(f"  [+] {'otx_pivot':28s} {len(otx_pivots):7d} domains  (local, targets excluded)")
                discovery["otx_pivot"] = otx_pivots
        except Exception as e:
            log(f"  [!] Failed to read {otx_file}: {e}")

    # 7. Shodan favicon pivot results (shodan_pivot.py -> infrastructure sharing)
    shodan_file = "data/shodan_pivots.csv"
    if os.path.exists(shodan_file):
        try:
            shodan_pivots = set()
            with open(shodan_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    domains_raw = row.get("domains", "")
                    for d in domains_raw.split(";"):
                        d = normalize_domain(d)
                        if d in targets:
                            continue
                        if is_valid_domain(d):
                            shodan_pivots.add(d)
            if shodan_pivots:
                log(f"  [+] {'shodan_pivot':28s} {len(shodan_pivots):7d} domains  (local, targets excluded)")
                discovery["shodan_pivot"] = shodan_pivots
        except Exception as e:
            log(f"  [!] Failed to read {shodan_file}: {e}")

    return discovery


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dea-out", default="data/dea_domains.csv")
    ap.add_argument("--discovery-out", default="data/discovery_domains.csv")
    ap.add_argument("--pipeline-out", default="data/pipeline_input.csv",
                    help="Combined DEA + discovery for pipeline consumption")
    ap.add_argument("--high-out", default="data/high_abuse_domains.csv")
    ap.add_argument("--allow-out", default="data/dea_allowlist.csv")
    ap.add_argument("--targets-file", default="data/targets.txt")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)

    ap.add_argument("--include-stopforumspam", action="store_true",
                    help="Include StopForumSpam toxic domain lists into high-abuse output")
    ap.add_argument("--include-deviceandbrowserinfo", action="store_true",
                    help="Include deviceandbrowserinfo disposable API")
    ap.add_argument("--device-mode", choices=["dea", "high"], default="dea",
                    help="Where to place deviceandbrowserinfo domains")
    # CHANGED: allowlist filtering is now ON by default
    ap.add_argument("--no-filter-allowlist", action="store_true",
                    help="Disable allowlist subtraction from DEA output (filtering is ON by default)")

    args = ap.parse_args()

    # ---- Load target brands for exclusion ----
    targets = load_targets(args.targets_file)
    if targets:
        log(f"[*] Loaded {len(targets)} target brands for exclusion from discovery")

    # ---- DEA sources (strict disposable/burner/provider lists ONLY) ----
    dea_sources: List[Tuple[str, str, Callable[[str], Set[str]]]] = [
        ("adam_loving_gist",
         "https://gist.githubusercontent.com/adamloving/4401361/raw/temporary-email-address-domains",
         parse_line_list),
        ("mailchecker_list",
         "https://raw.githubusercontent.com/FGRibreau/mailchecker/master/list.txt",
         parse_line_list),
        ("andreis_disposable",
         "https://raw.githubusercontent.com/andreis/disposable-email-domains/master/domains.txt",
         parse_line_list),
        ("pypi_blocklist_conf",
         "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf",
         parse_line_list),
        ("yopmail_alternates_html",
         "https://yopmail.com/alternate-domains",
         None),  # special handler below
        ("disposable_repo_domains",
         "https://raw.githubusercontent.com/disposable/disposable-email-domains/refs/heads/master/domains.txt",
         parse_line_list),
        ("fakefilter",
         "https://raw.githubusercontent.com/7c/fakefilter/refs/heads/main/txt/data.txt",
         parse_line_list),
        ("wesbos_burner",
         "https://raw.githubusercontent.com/wesbos/burner-email-providers/refs/heads/master/emails.txt",
         parse_line_list),
        ("propaganistas_domains_json",
         "https://raw.githubusercontent.com/Propaganistas/Laravel-Disposable-Email/refs/heads/master/domains.json",
         parse_json_domains),
        ("tempemail_mxrecords_csv",
         "https://raw.githubusercontent.com/infiniteloopltd/TempEmailDomainMXRecords/refs/heads/master/TempEmailDomainMXRecords.csv",
         parse_tempemail_mx_csv),
        ("doodad_labs_blocklist",
         "https://raw.githubusercontent.com/doodad-labs/disposable-email-domains/refs/heads/main/data/domains.txt",
         parse_line_list),
    ]

    # ---- Allowlist source ----
    allowlist_url = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/allowlist.conf"

    # ---- High-abuse sources (opt-in, separate signal) ----
    high_sources: List[Tuple[str, str, Callable[[str], Set[str]]]] = []
    if args.include_stopforumspam:
        high_sources += [
            ("stopforumspam_toxic_whole",
             "https://www.stopforumspam.com/downloads/toxic_domains_whole.txt",
             parse_line_list),
            ("stopforumspam_toxic_filtered",
             "https://www.stopforumspam.com/downloads/toxic_domains_whole_filtered.txt",
             parse_line_list),
        ]
    if args.include_deviceandbrowserinfo:
        device_url = "https://deviceandbrowserinfo.com/api/emails/disposable"
        if args.device_mode == "dea":
            dea_sources.append(("deviceandbrowserinfo_api", device_url, parse_json_domains))
        else:
            high_sources.append(("deviceandbrowserinfo_api", device_url, parse_json_domains))

    # ════════════════════════════════════════════════════════════
    # PHASE 1: Collect DEA domains (community lists only)
    # ════════════════════════════════════════════════════════════
    log("[*] Fetching DEA sources (community disposable email lists)...")
    dea: Set[str] = set()

    for name, url, parser in dea_sources:
        if name == "yopmail_alternates_html":
            try:
                t0 = time.time()
                html = fetch(url, args.timeout)
                candidates = set(re.findall(r"\b[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}\b|\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,63}\b", html))
                doms = set()
                for c in candidates:
                    d = normalize_domain(c)
                    if is_valid_domain(d):
                        doms.add(d)
                dt = time.time() - t0
                log(f"  [+] {name:28s} {len(doms):7d} domains  ({dt:0.1f}s)")
                dea |= doms
            except Exception as e:
                log(f"  [!] {name:28s} FAILED  ({type(e).__name__}: {e})")
            continue

        doms, _ = safe_fetch_parse(name, url, parser, args.timeout)
        dea |= doms

    log(f"[*] DEA merged total (pre-allowlist): {len(dea)}")

    # ════════════════════════════════════════════════════════════
    # PHASE 2: Fetch and apply allowlist
    # ════════════════════════════════════════════════════════════
    log("[*] Fetching DEA allowlist...")
    allow: Set[str] = set()
    allow, err = safe_fetch_parse("dea_allowlist_conf", allowlist_url, parse_line_list, args.timeout)
    log(f"[*] Allowlist total: {len(allow)}")
    write_csv(allow, args.allow_out)
    log(f"[*] Wrote allowlist CSV: {args.allow_out}")

    # Apply allowlist (ON by default now)
    if not args.no_filter_allowlist:
        dea_before = len(dea)
        dea -= allow
        log(f"[*] DEA after allowlist filter: {len(dea)}  (removed {dea_before - len(dea)})")
    else:
        log("[*] WARNING: Allowlist filtering disabled via --no-filter-allowlist")

    # Also exclude target brands from DEA (defense in depth)
    dea_before = len(dea)
    dea -= targets
    if dea_before - len(dea) > 0:
        log(f"[*] DEA after target brand exclusion: {len(dea)}  (removed {dea_before - len(dea)} target brands)")

    write_csv(dea, args.dea_out)
    log(f"[*] Wrote DEA CSV: {args.dea_out}  ({len(dea)} domains)")

    # ════════════════════════════════════════════════════════════
    # PHASE 3: Collect discovery domains (SEPARATE from DEA)
    # ════════════════════════════════════════════════════════════
    log("[*] Collecting discovery artifacts (separate from DEA)...")
    discovery = collect_discovery_domains(targets)

    # Remove any discovery domains already in DEA (they'll be covered there)
    total_discovery = 0
    for source_type in discovery:
        discovery[source_type] -= dea
        total_discovery += len(discovery[source_type])

    if discovery:
        write_csv_with_source(discovery, args.discovery_out)
        log(f"[*] Wrote discovery CSV: {args.discovery_out}  ({total_discovery} domains, DEA overlap removed)")
    else:
        log("[*] No discovery artifacts found.")

    # ════════════════════════════════════════════════════════════
    # PHASE 4: Build combined pipeline input
    # ════════════════════════════════════════════════════════════
    log("[*] Building combined pipeline input...")
    pipeline_sources: Dict[str, Set[str]] = {"dea": dea}
    pipeline_sources.update(discovery)
    write_csv_with_source(pipeline_sources, args.pipeline_out)
    pipeline_total = sum(len(v) for v in pipeline_sources.values())
    log(f"[*] Wrote pipeline input: {args.pipeline_out}  ({pipeline_total} domains)")

    # ════════════════════════════════════════════════════════════
    # PHASE 5: High-abuse (optional)
    # ════════════════════════════════════════════════════════════
    log("[*] Fetching high-abuse sources (optional)...")
    high: Set[str] = set()
    if not high_sources:
        log("  [-] No high-abuse sources enabled.")
    else:
        for name, url, parser in high_sources:
            doms, _ = safe_fetch_parse(name, url, parser, args.timeout)
            high |= doms

    high -= dea
    if not args.no_filter_allowlist:
        high -= allow
    high -= targets

    log(f"[*] High-abuse total (deduped): {len(high)}")
    write_csv(high, args.high_out)
    log(f"[*] Wrote high-abuse CSV: {args.high_out}")

    # ════════════════════════════════════════════════════════════
    # Summary
    # ════════════════════════════════════════════════════════════
    log("")
    log("=" * 60)
    log("  MERGE SUMMARY")
    log("=" * 60)
    log(f"  DEA domains (clean):           {len(dea):>8,}")
    for src, doms in sorted(discovery.items()):
        log(f"  Discovery ({src:16s}): {len(doms):>8,}")
    log(f"  Pipeline total (DEA+discovery): {pipeline_total:>8,}")
    log(f"  High-abuse:                     {len(high):>8,}")
    log(f"  Allowlist:                       {len(allow):>8,}")
    log(f"  Target brands excluded:          {len(targets):>8,}")
    log("=" * 60)
    log("[*] Done.")


if __name__ == "__main__":
    main()
