# Design: Infrastructure Fingerprinting Engine (FP-XXXX)

**Date:** 2026-02-25
**Phase:** FLAME + domain_intel Master Plan — Phase 1
**Issue:** Build FP-XXXX Infrastructure Fingerprinting Engine

## Purpose

Detect fraud infrastructure based on metadata patterns (registrar, nameserver, MX, ASN) rather than visual screenshots or keyword heuristics. Each pattern is codified as a versioned YAML fingerprint that the matching engine evaluates against enriched domain data.

## Architecture: Per-file YAML + Linear Scan Matcher (Approach 1)

Each fingerprint is a standalone YAML file in `config/fingerprints/`. The engine loads all files at startup, then iterates every domain row against every fingerprint. At 7 fingerprints x ~15k domains this is trivially fast (<1s). Indexing can be added later if the library grows past 100.

## YAML Schema

Files live at `config/fingerprints/FP-XXXX-slug.yaml`.

```yaml
id: "FP-0001"
name: "OVH cPanel DEA Infrastructure"
description: "Bulk DEA domains on OVH hosting using cprapid.com nameservers and temp-mail-pro.com MX"
version: 1

indicators:
  - field: asn              # maps to CSV column (aliases resolved by engine)
    match_type: exact       # exact | contains | regex | range
    value: "16276"
    required: true

  - field: ns
    match_type: contains
    value: "cprapid.com"
    required: true

  - field: mx
    match_type: contains
    value: "temp-mail-pro.com"
    required: false

confidence_base: 70

confidence_modifiers:
  - field: mx
    match_type: contains
    value: "temp-mail-pro.com"
    delta: +15

  - field: cc
    match_type: exact
    value: "FR"
    delta: +10

flame_tp_ids:
  - "TP-0003"

ttl_days: 30
```

### Field Alias Map

| YAML field | CSV column |
|---|---|
| `ns` | `nameservers` |
| `mx` | `primary_mx` |
| `registrar` | `registry` |
| `country` | `cc` |
| `title` | `http_title` |

Direct CSV column names (`asn`, `nameservers`, `primary_mx`, etc.) also work without aliasing.

### Match Types

| Type | Logic |
|---|---|
| `exact` | Case-insensitive string equality |
| `contains` | Case-insensitive substring check (works on semicolon-separated fields) |
| `regex` | `re.search(value, field_data, re.IGNORECASE)` |
| `range` | Numeric: `low-high` inclusive bounds |

### Scoring

1. All `required: true` indicators must pass (AND). If any fails, fingerprint does not match.
2. `required: false` indicators do not gate the match — they only participate via modifiers.
3. `confidence = clamp(confidence_base + sum(matching modifier deltas), 0, 100)`
4. A single domain can match multiple fingerprints (each is a separate output row).

## Matching Engine: `scripts/match_fingerprints.py`

### Loading Phase

- `glob("config/fingerprints/*.yaml")` → parse each with `yaml.safe_load()`
- Validate required keys: `id`, `name`, `indicators`, `confidence_base`
- Validate each indicator has: `field`, `match_type`, `value`, `required`
- Validate `match_type` is one of: `exact`, `contains`, `regex`, `range`
- Sort fingerprints by `id` for deterministic evaluation order

### Matching Phase (per domain row)

```
for each fingerprint:
    1. Check all required indicators (AND)
       - Resolve field aliases
       - Apply match_type logic
       - If ANY required indicator fails → skip fingerprint
    2. Calculate confidence:
       score = confidence_base
       for each modifier where condition matches:
           score += delta
       clamp(score, 0, 100)
    3. Build evidence string: "asn=16276;nameservers~cprapid.com"
    4. Emit row: (domain, fp_id, fp_name, confidence, flame_tp_ids, evidence)
```

### CLI Interface

```
python scripts/match_fingerprints.py \
  --input data/dea_domains_probed.csv \
  --output data/fingerprint_matches.csv
```

Defaults to those paths if no args given.

### Output: `data/fingerprint_matches.csv`

```
domain, fp_id, fp_name, confidence, flame_tp_ids, evidence
```

## Input Data

Primary input: `data/dea_domains_probed.csv` — the richest enrichment output with all infrastructure fields:

```
domain, primary_mx, mx_ip, asn, asn_name, bgp_prefix, cc, registry,
mx_records, nameservers, risk_tags, error, rbl_hits, creation_date,
age_days, otx_risk, http_status, http_title, http_server, https_status,
https_title, https_server, flame_tp_ids
```

## Initial Fingerprints (7)

| ID | Name | Key Indicators | FLAME TP |
|---|---|---|---|
| FP-0001 | OVH cPanel DEA | ASN 16276 + cprapid.com NS + temp-mail-pro MX | TP-0003 |
| FP-0002 | Alibaba Sideloading | ASN 45102 + sideload keywords + DEA MX | TP-0012 |
| FP-0003 | Crypto Finance Co-hosting | Financial keywords + DEA MX + shared hosting | TP-0017 |
| FP-0004 | Gname + Cloudflare China | Gname registrar + Cloudflare NS + Chinese ASN | TP-0017 |
| FP-0005 | GoDaddy Bulk Registration | GoDaddy registry + bulk registration pattern | TP-0019 |
| FP-0006 | Shell Domain MX Cluster | Shared non-standard MX + no web content + short-lived | TP-0003 |
| FP-0007 | Typosquat Evasion Infra | dnstwist match + 301/302 redirect + active MX | TP-0012 |

## Pipeline Integration

### Workflow position (update_intelligence.yml)

```
[Merge Results]           ← merge_results.py
[Infrastructure Intel]    ← asn_intel.py, vpn_intel.py, tor_intel.py
[Data Hygiene]            ← clean_data.py, enrich_asns.py
  ↓
[Fingerprint Matching]    ← NEW: match_fingerprints.py
  ↓
[Triage Domains]          ← triage_domains.py (consumes fingerprint_matches.csv)
[Shodan Enrichment]       ...
```

### Triage integration

In `triage_domains.py`, add a new Priority 0 check before the existing FLAME TP check:
- Load `data/fingerprint_matches.csv` into a dict keyed by domain
- If a domain has a match: `priority=0, reason="FP-0001: OVH cPanel DEA (conf: 85)", flame_tp_ids=TP-0003`

## Testing Strategy

`tests/test_fingerprints.py` — 15+ test functions, pytest, no I/O or network.

**Schema validation (3):** valid load, missing required key raises ValueError, unknown match_type raises ValueError.

**Match type logic (5):** exact, contains, regex, range, case-insensitive behavior.

**Scoring logic (4):** base-only, positive delta, negative delta, clamp to 0-100.

**Integration logic (3+):** multi-fingerprint match, zero match, required vs non-required, field alias resolution, empty/missing field graceful handling.

## Error Handling

- Malformed YAML: `log.error()` with filename, skip that fingerprint, continue loading others
- Missing CSV column for a field: treat as empty string → indicator does not match
- Invalid regex in fingerprint: `log.error()` at load time, skip that indicator
- Follow `shared/retry.py` pattern: specific exceptions, structured logging
