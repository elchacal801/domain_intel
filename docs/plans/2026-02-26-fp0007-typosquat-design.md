# FP-0007 Typosquat Evasion Infrastructure — Design Document

**Date:** 2026-02-26
**Status:** Approved
**Scope:** domain_intel + flame-fraud repos

## Problem Statement

FP-0007 ("Typosquat Evasion Infrastructure") cannot fire because:

1. **Redirect blindness**: `probe_web.py` uses `allow_redirects=True`, so `http_status` always shows the final status (200), never the initial 301/302. The FP-0007 indicator `http_status regex ^3\d\d$` can never match.
2. **No dnstwist cross-reference**: The fingerprint requires `risk_tags contains "typosquat"`, but there is no enrichment step that joins dnstwist output (`data/potential_typosquats.csv`) back into the pipeline CSV.
3. **FLAME gap**: Threat paths lack "Evasion Techniques" sections documenting adversary behaviors like strategic HTTP redirects and domain sale page camouflage.

This design addresses all three gaps based on CrowdStrike Counter Adversary Operations research on "Dual-Purpose Domains" and "Domain Sale Page Camouflage."

## Design Decisions

### 1. Redirect Capture — Modify probe_web.py

**Approach:** Use `response.history` to extract the initial redirect status and target without changing the existing `allow_redirects=True` behavior.

In the `fetch()` function, after the response is received:
```python
if response.history:
    result["redirect_status"] = str(response.history[0].status)
    result["redirect_target"] = str(response.history[0].headers.get("Location", ""))
```

**New columns added to probe output:**
- `http_redirect_status` — Initial HTTP status (301/302) if redirect occurred, empty otherwise
- `http_redirect_target` — Location header value from the initial redirect

**Why not `allow_redirects=False`?** That would break existing `http_status` and `http_title` columns that depend on following redirects to the final destination. Using `response.history` preserves backward compatibility.

### 2. dnstwist Cross-Reference — New `enrich_dnstwist.py`

**Approach:** Create a pre-enrichment script that joins the pipeline CSV against `data/potential_typosquats.csv` before fingerprinting runs.

**Input:** `data/dea_domains_probed.csv` (after probe_web.py)
**Lookup:** `data/potential_typosquats.csv` (17K+ rows with columns: `domain`, `dns_a`, `dns_aaaa`, `dns_mx`, `dns_ns`, `fuzzer`, `source_target`)

**New columns added:**
| Column | Type | Description |
|--------|------|-------------|
| `dnstwist_match` | bool | Domain found in potential_typosquats.csv |
| `dnstwist_fuzzer` | str | Fuzzer technique (e.g., homoglyph, addition) |
| `dnstwist_target` | str | Brand domain being impersonated |
| `redirects_to_brand` | bool | http_redirect_target contains dnstwist_target |
| `registrant_mismatch` | bool | registrant_org does not contain brand name |
| `ssl_present` | bool | https_status is non-empty (any response) |

**Derived logic:**
- `redirects_to_brand`: If `dnstwist_match` is True and `http_redirect_target` contains the `dnstwist_target` domain (case-insensitive substring match)
- `registrant_mismatch`: If `dnstwist_match` is True and the brand name (extracted from `dnstwist_target`, e.g., "amazon" from "amazon.com") is NOT found in `registrant_org` (case-insensitive). If `registrant_org` is empty, defaults to True (unknown = suspicious).

### 3. Updated FP-0007 YAML

Replace the current FP-0007 fingerprint with a redesigned schema:

```yaml
id: "FP-0007"
name: "Typosquat Evasion Infrastructure"
description: >
  Domains confirmed as typosquats (via dnstwist) exhibiting evasion
  behaviors: strategic redirects to brand, active MX, registrant
  mismatch, or sanctions matches.
version: 2

indicators:
  - field: dnstwist_match
    match_type: exact
    value: "True"
    required: true

confidence_base: 45

confidence_modifiers:
  - field: redirects_to_brand
    match_type: exact
    value: "True"
    delta: 30
  - field: primary_mx
    match_type: contains
    value: "."
    delta: 20
  - field: registrant_mismatch
    match_type: exact
    value: "True"
    delta: 15
  - field: http_title
    match_type: regex
    value: "(?i)(parked|for sale|buy this|domain for sale)"
    delta: 10
  - field: os_match_score
    match_type: range
    value: "70-100"
    delta: 20
  - field: ssl_present
    match_type: exact
    value: "True"
    delta: 5

flame_tp_ids:
  - "TP-0012"

ttl_days: 30
```

**Scoring examples:**
- Typosquat + redirects to brand + MX active: 45 + 30 + 20 = **95** (High)
- Typosquat + parked page + registrant mismatch: 45 + 10 + 15 = **70** (Medium)
- Typosquat alone (no evidence): **45** (Low, just flagged)

### 4. Pipeline Integration

Insert `enrich_dnstwist.py` into the workflow AFTER data hygiene and BEFORE fingerprinting:

```
Data Hygiene & Enrichment (clean_data.py, enrich_asns.py)
  → GLEIF → OpenSanctions → ICIJ
  → NEW: enrich_dnstwist.py
  → Infrastructure Fingerprinting (match_fingerprints.py)
  → Triage → Shodan → VT → PhishTank → ...
```

### 5. FLAME Threat Path Updates (flame-fraud repo)

**New section:** "Evasion Techniques" added between "CFPF Phase Mapping" and "Look Left / Look Right Analysis" in relevant threat paths.

**Threat paths to update:**
- **TP-0001** (Treasury Management ATO via Malvertising) — Strategic HTTP Redirect, Domain Sale Page Camouflage
- **TP-0002** (BEC Vendor Impersonation Wire Fraud) — Strategic HTTP Redirect, Geo-Targeted Content
- **TP-0017** (Pig Butchering) — Domain Sale Page Camouflage, Geo-Targeted Content

**Section format:**
```markdown
## Evasion Techniques

| Technique | Description | Detection Signal |
|-----------|-------------|------------------|
| Strategic HTTP Redirect | Typosquat domain 301/302 redirects to legitimate brand site | FP-0007: `redirects_to_brand=True` |
| Domain Sale Page Camouflage | Domain displays "for sale" page to evade automated scanners | FP-0007: `http_title` matches parked/sale pattern |
| Geo-Targeted Content | Different content served based on visitor geography | Manual verification required |
```

### 6. FLAME Methodology Doc

Create `docs/METHODOLOGY.md` in the flame-fraud repo documenting:
- Typosquat detection methodology (dnstwist fuzzing → DNS resolution → cross-reference)
- Known limitations (no Levenshtein scoring yet, geo-targeting requires manual verification)
- FP-0007 confidence scoring rationale

## Files Changed

### domain_intel repo
| File | Action | Description |
|------|--------|-------------|
| `scripts/probe_web.py` | Modify | Add redirect capture via `response.history` |
| `scripts/enrich_dnstwist.py` | Create | Cross-reference pipeline CSV against dnstwist output |
| `tests/test_dnstwist_enrich.py` | Create | Tests for enrich_dnstwist.py |
| `tests/test_probe_web.py` | Create | Tests for redirect capture in probe_web.py |
| `config/fingerprints/FP-0007-typosquat-evasion-infra.yaml` | Modify | Replace with v2 schema |
| `.github/workflows/update_intelligence.yml` | Modify | Add enrich_dnstwist.py step |

### flame-fraud repo
| File | Action | Description |
|------|--------|-------------|
| `ThreatPaths/TP-0001-*.md` | Modify | Add Evasion Techniques section |
| `ThreatPaths/TP-0002-*.md` | Modify | Add Evasion Techniques section |
| `ThreatPaths/TP-0017-*.md` | Modify | Add Evasion Techniques section |
| `docs/METHODOLOGY.md` | Create | Typosquat detection methodology and known limitations |

## Out of Scope

- Levenshtein scoring for fuzzy brand matching (future enhancement)
- Geo-targeted content detection automation (requires proxy infrastructure)
- STIX indicator generation for typosquat findings (follow-up work)
- Updating other threat paths beyond TP-0001, TP-0002, TP-0017
