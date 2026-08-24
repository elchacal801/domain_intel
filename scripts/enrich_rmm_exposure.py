#!/usr/bin/env python3
"""
enrich_rmm_exposure.py

Flags IP addresses exposing IP-KVM hardware or remote-management (RMM)
services.

Why this exists
---------------
2026 reporting on DPRK IT-worker operations (Google Cloud Threat Intelligence,
Nisos, runZero) describes laptop farms built on IP-KVM devices -- PiKVM,
TinyPilot, JetKVM -- with RMM tooling as the fallback layer where KVM hardware
is unavailable. Those connections are reported to originate predominantly from
Astrill VPN addresses, a population this pipeline already resolves.

MITRE ATT&CK covers the technique as T1219.003 (Remote Access Hardware), with
detection strategy DET0159 targeting TinyPilot and PiKVM specifically. DET0159
is host-based -- USB enumeration, EDID announcements, mount paths -- which is
unavailable to an external pipeline. This module provides the complementary
network-side view: which of our known-bad IPs expose such a device publicly.

Signatures come from runZero's IP-KVM survey (HTTP titles and favicon hashes)
and vendor default ports.

Design notes
------------
Detection uses Shodan *host lookups* rather than search queries. Host lookups
are already proven in this pipeline (enrich_shodan.py) and work on every plan
tier, so detection does not depend on search-filter entitlements.

ASN sweeps do use search, but combine the ASN filter with the signature set in
a single query per ASN, so a whole operator ASN costs roughly one credit rather
than one per host.

Usage:
  python enrich_rmm_exposure.py --ip-list data/known_campaign_ips.txt \
      --asn-seed data/kadnap_operator_asns.csv \
      --output data/rmm_exposure.csv --budget 100
"""

import argparse
import csv
import ipaddress
import json
import logging
import os
import sys
import time
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(__file__))

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

FIELDS = [
    "ip", "source", "asn", "kvm_detected", "kvm_products",
    "rmm_detected", "rmm_products", "exposure_evidence", "checked_date",
]

# --- Signatures -------------------------------------------------------------
# IP-KVM: HTTP title substrings and favicon.ico mmh3 hashes, per runZero's
# "Out-of-Band, Part 1: the new gen of IP KVMs & how to find them".
# Favicon hashes matter because titles are trivially customised -- a rebranded
# device still serves the stock favicon.

KVM_SIGNATURES: Dict[str, Dict] = {
    "PiKVM":            {"titles": ["pikvm", "pi-kvm"], "favicons": [-1040945478, -692926325]},
    "TinyPilot":        {"titles": ["tinypilot"],       "favicons": [-996415781]},
    "JetKVM":           {"titles": ["jetkvm"],          "favicons": [-1261329937]},
    "GLKVM":            {"titles": ["glkvm"],           "favicons": [-186012304]},
    "NanoKVM":          {"titles": ["nanokvm"],         "favicons": [1323732765]},
    "BliKVM":           {"titles": ["blikvm"],          "favicons": []},
    "Apache Guacamole": {"titles": ["apache guacamole", "guacamole"], "favicons": []},
}

# RMM: vendor default ports and product banner strings.
RMM_SIGNATURES: Dict[str, Dict] = {
    "RustDesk":   {"ports": [21115, 21116, 21117, 21118, 21119], "products": ["rustdesk"]},
    "AnyDesk":    {"ports": [7070],  "products": ["anydesk"]},
    "TeamViewer": {"ports": [5938],  "products": ["teamviewer"]},
    "VNC":        {"ports": [5900, 5901], "products": ["vnc", "realvnc", "tightvnc"]},
    "RDP":        {"ports": [3389],  "products": ["remote desktop", "ms-wbt-server"]},
    # Self-hosted RMM. Surfaced by passive DNS on 23.227.173.144, which served
    # mesh.<domain> beside rust.<domain> -- MeshCentral running next to
    # RustDesk. It has no fixed port worth matching (commonly 443 or 8086), so
    # it is identified by title and banner only.
    "MeshCentral": {"ports": [], "products": ["meshcentral"], "titles": ["meshcentral"]},
}

# 21118/21119 are RustDesk web-client ports only in some deployments; excluded
# from the default port match to avoid claiming any high port is RustDesk.
RUSTDESK_CORE_PORTS = {21115, 21116, 21117}


class Throttle:
    """Paces requests to a minimum interval.

    Shodan Basic allows roughly one request per second. A 143-IP run never hit
    that ceiling; ~90k will immediately.
    """

    def __init__(self, min_interval: float = 1.05):
        self.min_interval = min_interval
        self._last = None

    def wait(self):
        # One clock read per call: reading again after sleeping would also
        # charge the sleep itself against the next interval.
        now = time.monotonic()
        if self._last is not None:
            delta = now - self._last
            if delta < self.min_interval:
                pause = self.min_interval - delta
                time.sleep(pause)
                now += pause
        self._last = now


def parse_source(spec: str):
    """Split a "path[:column]" source spec, tolerating Windows drive letters."""
    head, sep, tail = spec.rpartition(":")
    if sep and tail and "/" not in tail and "\\" not in tail and len(tail) > 1:
        return head, tail
    return spec, "a_record"


def load_existing_results(path: str) -> Dict[str, Dict]:
    """Read the results ledger, keyed by IP. Missing file is simply empty."""
    out: Dict[str, Dict] = {}
    if not os.path.exists(path):
        return out
    try:
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                ip = (row.get("ip") or "").strip()
                if ip:
                    out[ip] = row
    except Exception as e:
        log.warning(f"Could not read existing results {path}: {e}")
    return out


def merge_results(existing: Dict[str, Dict], new: List[Dict]) -> List[Dict]:
    """Merge new findings into the ledger, newest record per IP winning.

    Rows not revisited this run are preserved untouched -- the ledger only ever
    grows or refreshes, never loses coverage.
    """
    merged = dict(existing)
    for row in new:
        ip = (row.get("ip") or "").strip()
        if ip:
            merged[ip] = row
    return [merged[k] for k in sorted(merged)]


def filter_unchecked(ips: List[str], existing: Dict[str, Dict], today: str,
                     max_age_days: int = 30) -> List[str]:
    """Drop IPs already checked within max_age_days.

    This is what makes progress independent of the SQLite cache: the ledger
    itself records what has been covered, so cache expiry cannot silently
    restart the sweep from the beginning.
    """
    from datetime import date
    def _stale(rec):
        d = (rec.get("checked_date") or "").strip()
        if not d:
            return True
        try:
            a = date.fromisoformat(today) - date.fromisoformat(d)
        except ValueError:
            return True
        return a.days >= max_age_days
    return [ip for ip in ips if ip not in existing or _stale(existing[ip])]


def _iter_services(host: Dict):
    for entry in host.get("data") or []:
        if isinstance(entry, dict):
            yield entry


def classify_host(host: Dict) -> Dict:
    """Classify a Shodan host record for KVM / RMM exposure.

    Pure function: takes the record, returns findings. No network access, so
    the signature logic is fully testable.
    """
    kvm_found: List[str] = []
    rmm_found: List[str] = []
    evidence: List[str] = []

    for svc in _iter_services(host):
        port = svc.get("port")
        product = (svc.get("product") or "").lower()
        http = svc.get("http") or {}
        title = (http.get("title") or "").lower()
        favicon = ((http.get("favicon") or {}).get("hash"))

        # --- IP-KVM ---
        for name, sig in KVM_SIGNATURES.items():
            hit = None
            if title and any(t in title for t in sig.get("titles", [])):
                hit = "title"
            elif favicon is not None and favicon in sig.get("favicons", []):
                hit = "favicon"
            if hit:
                if name not in kvm_found:
                    kvm_found.append(name)
                evidence.append(f"{port}:{name}({hit})")

        # --- RMM ---
        for name, sig in RMM_SIGNATURES.items():
            ports = sig.get("ports", [])
            if name == "RustDesk":
                ports = [p for p in ports if p in RUSTDESK_CORE_PORTS]
            hit = None
            if ports and port in ports:
                hit = "port"
            elif product and any(p in product for p in sig.get("products", [])):
                hit = "product"
            elif title and any(x in title for x in sig.get("titles", [])):
                hit = "title"
            if hit:
                if name not in rmm_found:
                    rmm_found.append(name)
                evidence.append(f"{port}:{name}({hit})")

    return {
        "kvm_detected": bool(kvm_found),
        "kvm_products": ";".join(kvm_found),
        "rmm_detected": bool(rmm_found),
        "rmm_products": ";".join(rmm_found),
        "exposure_evidence": "; ".join(evidence),
    }


def load_ip_list(path: str) -> List[str]:
    """Read a plain IP list, skipping blanks and # comments."""
    ips: List[str] = []
    if not os.path.exists(path):
        log.warning(f"IP list not found: {path}")
        return ips
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ipaddress.ip_address(line)
            except ValueError:
                continue
            if line not in ips:
                ips.append(line)
    log.info(f"Loaded {len(ips)} IPs from {path}")
    return ips


def load_ips_from_csv(path: str, column: str) -> List[str]:
    """Unique, valid IPs from a column of a domain CSV, in first-seen order.

    FP-0011 matches domain rows, so the addresses worth checking are the ones
    those rows resolve to. Invalid and blank values are skipped rather than
    raising -- a_record legitimately holds CNAMEs and error strings.
    """
    ips: List[str] = []
    seen = set()
    if not os.path.exists(path):
        log.warning(f"CSV not found: {path}")
        return ips
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if column not in (reader.fieldnames or []):
            log.warning(f"Column '{column}' not in {path}; columns: {reader.fieldnames}")
            return ips
        for row in reader:
            v = (row.get(column) or "").strip()
            if not v or v in seen:
                continue
            try:
                ipaddress.ip_address(v)
            except ValueError:
                continue
            seen.add(v)
            ips.append(v)
    log.info(f"Loaded {len(ips)} unique IPs from {column} in {path}")
    return ips


def load_asn_seed(path: str) -> List[Dict]:
    """Read the curated operator-ASN seed (ASN,Name,... )."""
    rows: List[Dict] = []
    if not os.path.exists(path):
        log.info(f"No ASN seed at {path}; skipping ASN sweep")
        return rows
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            asn = (row.get("ASN") or "").strip()
            if asn:
                rows.append(row)
    log.info(f"Loaded {len(rows)} operator ASNs from {path}")
    return rows


def kvm_search_query() -> str:
    """One query covering every KVM title, for ASN sweeps.

    Shodan's query language supports neither boolean OR nor parentheses.
    Multiple alternatives for a single filter are comma-separated, so all
    titles go into one http.title: filter. Combining that with the ASN filter
    costs about one credit per ASN, instead of one host lookup per address in
    the range.
    """
    titles = sorted({t for sig in KVM_SIGNATURES.values() for t in sig.get("titles", [])})
    return "http.title:" + ",".join(f'"{t}"' for t in titles)


def kvm_favicon_queries() -> List[str]:
    """One query per known KVM favicon hash.

    Shodan cannot OR multiple values for http.favicon.hash the way it can for
    http.title, so each hash needs its own query. Favicons matter because a
    title is trivially customised while the stock favicon usually survives --
    a retitled PiKVM is invisible to a title-only sweep.
    """
    hashes = sorted({h for sig in KVM_SIGNATURES.values() for h in sig.get("favicons", [])})
    return [f"http.favicon.hash:{h}" for h in hashes]


def asn_sweep_queries(asn: str) -> List[str]:
    """Every sweep query for one ASN: the combined title filter, then one per
    favicon hash. Costs len(favicons)+1 searches per ASN instead of 1, which is
    still far cheaper than a host lookup per address in the range."""
    return [f"asn:{asn} {kvm_search_query()}"] + [f"asn:{asn} {q}" for q in kvm_favicon_queries()]


def lookup_host(api, ip: str, cache=None, retries: int = 3, throttle=None):
    """Shodan host lookup, cached.

    Returns (record, used_api). record is None when the IP is unknown to
    Shodan. used_api is False on a cache hit, so cached results do not consume
    the run's API budget -- otherwise a re-run burns budget without making a
    single call.
    """
    key = f"rmm_host:{ip}"
    if cache is not None:
        hit = cache.get(key, max_age_days=30)
        if hit is not None:
            return hit, False
    rec = None
    for attempt in range(1, retries + 1):
        if throttle is not None:
            throttle.wait()
        try:
            # minify=False: the per-service banner detail (product, http.title,
            # favicon) is exactly what the signatures match on.
            rec = api.host(ip, minify=False)
            break
        except Exception as e:
            msg = str(e)
            if "No information available" in msg:
                # A genuine "not in Shodan" is an answer, not a failure; do not
                # spend retries on it.
                log.debug(f"{ip}: not in Shodan")
                return None, True
            if attempt >= retries:
                log.warning(f"{ip}: lookup failed after {retries} attempts: "
                            f"{type(e).__name__}: {msg}")
                return None, True
            time.sleep(min(2 ** attempt, 30))
    if rec is None:
        return None, True
    if cache is not None:
        try:
            cache.set(key, rec)
        except Exception:
            pass
    return rec, True


ANNOTATION_FIELDS = [
    "kvm_detected", "kvm_products", "rmm_detected", "rmm_products",
    "exposure_evidence",
]


def annotate_csv(input_path: str, output_path: str, findings: Dict[str, Dict],
                 ip_column: str = "a_record") -> int:
    """Join findings onto a domain CSV, keyed by its IP column.

    Mirrors enrich_proxy_check.py, so the fingerprint engine can match these
    columns the same way FP-0010 matches proxy_detected / proxy_type.

    Booleans are written as yes/no to match the existing enrichment columns.
    Rows without a finding get an explicit "no" rather than a blank, so a
    fingerprint can distinguish "checked, clean" from "never checked".

    Returns the number of rows annotated with a positive finding.
    """
    with open(input_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)

    for name in ANNOTATION_FIELDS:
        if name not in fieldnames:
            fieldnames.append(name)

    annotated = 0
    for row in rows:
        ip = (row.get(ip_column) or "").strip()
        found = findings.get(ip)
        if found:
            row["kvm_detected"] = "yes" if found["kvm_detected"] else "no"
            row["rmm_detected"] = "yes" if found["rmm_detected"] else "no"
            row["kvm_products"] = found["kvm_products"]
            row["rmm_products"] = found["rmm_products"]
            row["exposure_evidence"] = found["exposure_evidence"]
            if found["kvm_detected"] or found["rmm_detected"]:
                annotated += 1
        else:
            row.setdefault("kvm_detected", "no")
            row.setdefault("rmm_detected", "no")
            for name in ("kvm_products", "rmm_products", "exposure_evidence"):
                row.setdefault(name, "")

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    log.info(f"Annotated {annotated} row(s) with exposure in {output_path}")
    return annotated


def main():
    parser = argparse.ArgumentParser(
        description="Flag IPs exposing IP-KVM or remote-management services")
    parser.add_argument("--ip-list", default="data/known_campaign_ips.txt",
                        help="Plain-text IP list (# comments allowed)")
    parser.add_argument("--asn-seed", default="data/kadnap_operator_asns.csv",
                        help="Curated operator-ASN CSV for the ASN sweep")
    parser.add_argument("--output", default="data/rmm_exposure.csv")
    parser.add_argument("--budget", type=int, default=100,
                        help="Maximum Shodan calls this run")
    parser.add_argument("--skip-asn-sweep", action="store_true",
                        help="Host lookups only; makes no search queries")
    parser.add_argument("--source", action="append", default=[],
                        metavar="PATH[:COLUMN]",
                        help="CSV to source IPs from, repeatable. Column defaults "
                             "to a_record, e.g. data/vpn_relay_ips.csv:ip")
    parser.add_argument("--domain-csv", default=None,
                        help="Deprecated alias for a single --source")
    parser.add_argument("--recheck-days", type=int, default=30,
                        help="Skip IPs already checked within this many days")
    parser.add_argument("--checkpoint-every", type=int, default=100,
                        help="Flush the results ledger every N lookups")
    parser.add_argument("--annotate", default=None,
                        help="Domain CSV to join findings onto (adds columns in place)")
    parser.add_argument("--ip-column", default="a_record",
                        help="Column in --annotate holding the IP to match")
    args = parser.parse_args()

    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:
        pass

    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        log.error("SHODAN_API_KEY not set")
        return 1

    import shodan
    api = shodan.Shodan(api_key)

    try:
        from shodan_utils import ShodanCache
        cache = ShodanCache()
    except Exception as e:
        log.warning(f"Cache unavailable ({e}); continuing uncached")
        cache = None

    from datetime import date
    today = date.today().isoformat()
    results: List[Dict] = []
    spent = 0

    # The results file is the progress ledger. Basing resumption on it rather
    # than on the SQLite cache means a cache expiry or loss cannot silently
    # restart the sweep from the beginning.
    existing = load_existing_results(args.output)
    log.info(f"Ledger: {len(existing)} IPs already recorded in {args.output}")

    throttle = Throttle()
    results: List[Dict] = []

    def checkpoint():
        rows = merge_results(existing, results)
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        return len(rows)

    # --- Assemble the work list ------------------------------------------
    sources = [(args.ip_list, None)]
    if args.domain_csv:
        sources.append((args.domain_csv, args.ip_column))
    for spec in args.source:
        sources.append(parse_source(spec))

    work: List[tuple] = []
    seen = set()
    for path, column in sources:
        ips = load_ip_list(path) if column is None else load_ips_from_csv(path, column)
        label = os.path.basename(path)
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                work.append((ip, label))

    todo = filter_unchecked([ip for ip, _ in work], existing, today, args.recheck_days)
    todo_set = set(todo)
    label_of = dict(work)
    log.info(f"{len(work)} unique IPs across {len(sources)} source(s); "
             f"{len(todo)} need checking, {len(work) - len(todo)} already fresh")

    # --- Look up ----------------------------------------------------------
    for i, ip in enumerate(todo, 1):
        if spent >= args.budget:
            log.info(f"Budget of {args.budget} reached; {len(todo) - i + 1} IPs "
                     f"deferred to the next run (the ledger carries progress)")
            break
        rec, used_api = lookup_host(api, ip, cache, throttle=throttle)
        if used_api:
            spent += 1
        if rec is None:
            continue
        found = classify_host(rec)
        if found["kvm_detected"] or found["rmm_detected"]:
            log.info(f"  {ip}: {found['exposure_evidence']}")
        results.append({
            "ip": ip,
            "source": label_of.get(ip, ""),
            "asn": rec.get("asn", ""),
            "checked_date": today,
            **found,
        })
        if args.checkpoint_every and len(results) % args.checkpoint_every == 0:
            n = checkpoint()
            log.info(f"  checkpoint: {n} rows in ledger ({spent} lookups this run)")

    # --- Operator ASN sweep ------------------------------------------------
    if not args.skip_asn_sweep:
        for row in load_asn_seed(args.asn_seed):
            if spent >= args.budget:
                log.warning("Budget reached; ASN sweep truncated")
                break
            asn = row["ASN"].strip()
            found_total = 0
            matches = []
            for q in asn_sweep_queries(asn):
                if spent >= args.budget:
                    break
                throttle.wait()
                try:
                    res = api.search(q, limit=100)
                    spent += 1
                except Exception as e:
                    log.warning(f"{asn}: search failed ({q}): {type(e).__name__}: {e}")
                    continue
                found_total += res.get("total", 0)
                matches.extend(res.get("matches", []))
            log.info(f"  {asn} ({row.get('Name','')}): {found_total} KVM-signature match(es)")
            for match in matches:
                found = classify_host({"data": [match]})
                results.append({
                    "ip": match.get("ip_str", ""),
                    "source": f"asn_sweep:{asn}",
                    "asn": asn,
                    "checked_date": today,
                    **found,
                })

    # Write through the ledger merge, never the raw run results: writing
    # `results` alone would discard every IP checked on previous runs.
    total = checkpoint()

    if args.annotate:
        # Annotate from the whole ledger, not just this run, so domains whose
        # IPs were checked days ago keep their columns.
        annotate_csv(args.annotate, args.annotate,
                     load_existing_results(args.output), args.ip_column)

    hits = [r for r in results if r.get("kvm_detected") or r.get("rmm_detected")]
    log.info(f"Ledger holds {total} IPs in {args.output}; "
             f"{len(results)} checked this run, {len(hits)} with exposure")
    log.info(f"Shodan calls used: {spent}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
