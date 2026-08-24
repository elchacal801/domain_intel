#!/usr/bin/env python3
"""
hunt_kvm.py

Proactively hunts for internet-exposed IP-KVM devices via Shodan.

Why a separate hunt
-------------------
hunt_campaign.py hunts disposable-email infrastructure and writes into
data/known_campaign_ips.txt. IP-KVM findings are a different threat with a
different consumer (FP-0011), so mixing them would pollute that baseline and
make campaign attribution ambiguous. This keeps its own baseline and history.

Why IP-KVM
----------
2026 DPRK IT-worker reporting describes laptop farms built on IP-KVM hardware:
a facilitator racks company laptops while the operator drives them remotely over
KVM. No software runs on the host, so endpoint tooling sees nothing. MITRE
covers it as T1219.003 (Remote Access Hardware).

Query selection (measured against live Shodan, 2026-08-24)
----------------------------------------------------------
    http.title:"pikvm","pi-kvm","tinypilot",...        1397   <- broadest
    http.html:"pikvm"                                   664
    ssl:"PiKVM"                                         560
    http.title:"PiKVM"                                  547
    http.favicon.hash:-1040945478                       479
    http.html:"nanokvm"                                 431
    http.html:"pikvm" -port:443 -port:80                338   <- half are off 443/80
    http.html:"jetkvm"                                  100
    http.html:"tinypilot"                                70

Rejected:
    ssl.jarm:27d28d28d000...     10439 hosts -- a TLS-stack fingerprint shared
                                 with ordinary nginx, not a device signature.
                                 Never used unqualified.
    ssl.cert.issuer.CN:"PiKVM"       7 -- Shodan does not index the cert
                                 organisation, despite 7531/10000 Silent Push
                                 records carrying issuer O=PiKVM.

Coverage caveat
---------------
Shodan surfaces roughly 600 PiKVM hosts where Silent Push observes 14,000+.
Shodan is therefore a supplementary channel here, not the primary one; the
Silent Push export seeds the baseline so the hunt reports genuinely new hosts
rather than re-reporting that population.

Usage:
  python hunt_kvm.py [--budget 20] [--dry-run]
"""

import argparse
import csv
import ipaddress
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# The key check lives in main(). Exiting at import time is what kept
# hunt_campaign.py untested for so long.

BASELINE_FILES = [
    "data/vpn_seeds/kvm_silentpush_20260824.csv",   # 1,878 IPs, Silent Push
    "data/known_kvm_ips.txt",                        # manually curated additions
]
HISTORY_FILE = "data/kvm_hunt_history.csv"

# Comma-separated values OR correctly inside http.title. They do NOT inside
# http.html or http.favicon.hash -- a collapsed query there returns zero
# results, silently disabling it. Hence one query per body/favicon term.
QUERIES = [
    # Titles, all products, collapsed (~1397)
    'http.title:"pikvm","pi-kvm","tinypilot","jetkvm","nanokvm","glkvm","blikvm"',

    # Body content: survives a device having its title renamed
    'http.html:"pikvm"',
    'http.html:"nanokvm"',
    'http.html:"jetkvm"',
    'http.html:"tinypilot"',

    # Non-standard ports: roughly half of PiKVM hits are not on 443/80
    'http.html:"pikvm" -port:443 -port:80',

    # TLS banner
    'ssl:"PiKVM"',

    # Guacamole, qualified. Bare http.html:"guacamole" matches 12,780 hosts and
    # http.title:"Apache Guacamole" only 5; requiring both narrows to ~97,
    # which is reviewable. Guacamole is legitimate enterprise software, so it
    # is scored well below dedicated KVM hardware in FP-0011.
    'http.html:"guacamole" http.title:"Guacamole"',

    # Favicons: a rebranded device still serves the stock icon (runZero)
    'http.favicon.hash:-1040945478',   # PiKVM
    'http.favicon.hash:-692926325',    # PiKVM alt
    'http.favicon.hash:-996415781',    # TinyPilot
    'http.favicon.hash:-1261329937',   # JetKVM
    'http.favicon.hash:1323732765',    # NanoKVM
    'http.favicon.hash:-186012304',    # GLKVM
]

BUDGET_LIMIT = 20  # one credit per query, plus headroom

FIELDS = ["first_seen", "ip", "port", "query", "product", "org", "country", "title"]


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def load_baseline_ips(paths=None) -> set:
    """Union of every known-KVM IP, from CSV seeds and plain lists alike.

    IPv6 is preserved: the Silent Push seed contains IPv6 hosts, and dropping
    them would make the hunt re-report them as new on every run.
    """
    out = set()
    for path in (paths if paths is not None else BASELINE_FILES):
        p = Path(path)
        if not p.exists():
            continue
        try:
            if p.suffix.lower() == ".csv":
                with p.open(newline="", encoding="utf-8") as f:
                    for row in csv.DictReader(f):
                        ip = (row.get("ip") or "").strip()
                        if ip and _valid_ip(ip):
                            out.add(ip)
            else:
                for line in p.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and _valid_ip(line):
                        out.add(line)
        except Exception as e:
            print(f"[!] Could not read baseline {path}: {e}")
    return out


def load_history_ips(path: str = HISTORY_FILE) -> set:
    """IPs already reported by a previous hunt, so each is announced once."""
    out = set()
    p = Path(path)
    if not p.exists():
        return out
    try:
        with p.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                ip = (row.get("ip") or "").strip()
                if ip:
                    out.add(ip)
    except Exception as e:
        print(f"[!] Could not read history {path}: {e}")
    return out


def log_hit(match: dict, query: str, path: str = HISTORY_FILE) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    new_file = not p.exists()
    http = match.get("http") or {}
    with p.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        if new_file:
            w.writeheader()
        w.writerow({
            "first_seen": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "ip": match.get("ip_str", ""),
            "port": match.get("port", ""),
            "query": query,
            "product": match.get("product", ""),
            "org": match.get("org", ""),
            "country": (match.get("location") or {}).get("country_name", ""),
            "title": (http.get("title") or "").strip()[:120],
        })


def main() -> int:
    parser = argparse.ArgumentParser(description="Hunt internet-exposed IP-KVM devices")
    parser.add_argument("--budget", type=int, default=BUDGET_LIMIT)
    parser.add_argument("--dry-run", action="store_true",
                        help="List the queries without calling Shodan")
    args = parser.parse_args()

    if args.dry_run:
        for q in QUERIES:
            print(f"  {q}")
        return 0

    if not SHODAN_API_KEY:
        print("Error: SHODAN_API_KEY not found.")
        return 1

    import shodan
    api = shodan.Shodan(SHODAN_API_KEY)

    baseline = load_baseline_ips()
    history = load_history_ips()
    print(f"Baseline: {len(baseline)} known KVM IPs")
    print(f"History : {len(history)} previously reported")

    spent = 0
    new_count = 0
    for query in QUERIES:
        if spent >= args.budget:
            print(f"[!] Budget of {args.budget} reached; {len(QUERIES) - spent} "
                  f"queries not run")
            break
        try:
            results = api.search(query)
            spent += 1
        except Exception as e:
            print(f"[!] Query failed ({query}): {type(e).__name__}: {e}")
            continue

        total = results.get("total", 0)
        matches = results.get("matches", [])
        print(f"Query: {query}\n   {total} total, {len(matches)} on first page")

        for m in matches:
            ip = m.get("ip_str", "")
            if not ip or ip in baseline or ip in history:
                continue
            history.add(ip)
            new_count += 1
            title = ((m.get("http") or {}).get("title") or "").strip()[:60]
            print(f"::warning:: [NEW KVM] {ip}:{m.get('port')} "
                  f"{m.get('org','n/a')} | {title}")
            log_hit(m, query)

    print(f"\nDone. {new_count} new IP-KVM host(s); {spent} queries used.")
    # ALWAYS return 0. This runs inside the discovery job, which has no
    # continue-on-error, so a non-zero exit on findings would fail the job
    # and abort the whole pipeline. Findings surface via the ::warning::
    # annotations above, matching hunt_campaign.py's explicit rule.
    return 0


if __name__ == "__main__":
    sys.exit(main())
