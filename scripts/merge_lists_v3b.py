#!/usr/bin/env python3
"""
merge_lists_v3b.py

Builds three domain lists:
  1) dea_domains.csv        -> strict disposable/burner provider domains (deduped)
  2) high_abuse_domains.csv -> domains from "abuse-oriented" feeds (opt-in)
  3) dea_allowlist.csv      -> known false positives to exclude from DEA

Default behavior:
- Builds DEA from many sources (v2 + v3 + additional researched sources)
- Fetches allowlist.conf and writes dea_allowlist.csv
- Subtracts allowlist from DEA (recommended)
- Does NOT include StopForumSpam unless --include-stopforumspam is set
- DeviceAndBrowserInfo feed is optional (and can be routed to DEA or High)

Usage:
  python merge_lists_v3b.py
  python merge_lists_v3b.py --dea-out disposable_domains_full.csv
  python merge_lists_v3b.py --include-stopforumspam
  python merge_lists_v3b.py --include-deviceandbrowserinfo --device-mode dea
  python merge_lists_v3b.py --include-deviceandbrowserinfo --device-mode high
"""

import argparse
import csv
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dea-out", default="data/dea_domains.csv")
    ap.add_argument("--high-out", default="data/high_abuse_domains.csv")
    ap.add_argument("--allow-out", default="data/dea_allowlist.csv")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)

    ap.add_argument("--include-stopforumspam", action="store_true",
                    help="Include StopForumSpam toxic domain lists into high-abuse output")
    ap.add_argument("--include-deviceandbrowserinfo", action="store_true",
                    help="Include deviceandbrowserinfo disposable API")
    ap.add_argument("--device-mode", choices=["dea", "high"], default="dea",
                    help="Where to place deviceandbrowserinfo domains")
    ap.add_argument("--no-allowlist-filter", action="store_true",
                    help="Do NOT subtract allowlist from DEA/high-abuse outputs (not recommended)")

    args = ap.parse_args()

    # ---- DEA sources (strict disposable/burner/provider lists) ----
    # v2 sources
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
        # YOPmail alternates (HTML) – best-effort (some networks block / rate-limit)
        # We'll scrape by extracting domains that look like FQDNs in the page.
        ("yopmail_alternates_html",
         "https://yopmail.com/alternate-domains",
         None),  # special handler below
    ]

    # v3 / “modern mega-list inputs”
    dea_sources += [
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
         "https://raw.githubusercontent.com/doodad-labs/disposable-email-domains/master/disposable_email_blocklist.conf",
         parse_line_list),
    ]

    # ---- Allowlist source (separate output) ----
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

    # ---- Execute pulls ----
    log("[*] Fetching DEA sources...")
    dea: Set[str] = set()

    for name, url, parser in dea_sources:
        if name == "yopmail_alternates_html":
            # Special scrape: extract domains from the HTML by regex
            try:
                t0 = time.time()
                html = fetch(url, args.timeout)
                # Extract FQDNs (conservative)
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

    log("[*] Fetching DEA allowlist (separate output)...")
    allow: Set[str] = set()
    allow, err = safe_fetch_parse("dea_allowlist_conf", allowlist_url, parse_line_list, args.timeout)
    log(f"[*] Allowlist total: {len(allow)}")

    # Write allowlist as requested
    write_csv(allow, args.allow_out)
    log(f"[*] Wrote allowlist CSV: {args.allow_out}")

    # Apply allowlist filtering unless disabled
    if not args.no_allowlist_filter:
        dea_before = len(dea)
        dea -= allow
        log(f"[*] DEA after allowlist filter: {len(dea)}  (removed {dea_before - len(dea)})")
    else:
        log("[*] NOTE: Allowlist filtering disabled (--no-allowlist-filter).")

    # Write DEA output
    write_csv(dea, args.dea_out)
    log(f"[*] Wrote DEA CSV: {args.dea_out}")

    # High-abuse
    log("[*] Fetching high-abuse sources (optional)...")
    high: Set[str] = set()
    if not high_sources:
        log("  [-] No high-abuse sources enabled. (Use --include-stopforumspam and/or --include-deviceandbrowserinfo --device-mode high)")
    else:
        for name, url, parser in high_sources:
            doms, _ = safe_fetch_parse(name, url, parser, args.timeout)
            high |= doms

    # keep tiers clean: remove DEA overlap; also remove allowlist unless disabled
    high -= dea
    if not args.no_allowlist_filter:
        high -= allow

    log(f"[*] High-abuse total (deduped, minus DEA & allowlist): {len(high)}")

    write_csv(high, args.high_out)
    log(f"[*] Wrote high-abuse CSV: {args.high_out}")

    log("[*] Done.")


if __name__ == "__main__":
    main()
