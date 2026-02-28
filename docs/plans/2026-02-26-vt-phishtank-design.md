# Design: VirusTotal, PhishTank & URLhaus Integrations

**Date:** 2026-02-26
**Phase:** FLAME + domain_intel Master Plan — Phase 1
**Issue:** Integrate VirusTotal API + PhishTank/URLhaus bulk feeds

## Purpose

Add two threat intelligence enrichment scripts to the pipeline:
1. **VirusTotal** — Query VT API v3 for domain reputation and malicious engine verdicts on triaged candidates
2. **PhishTank + URLhaus** — Bulk download active phishing/malware feeds and cross-reference against all monitored domains

## Architecture

Two scripts following two established project patterns:

```
[enrich_virustotal.py]  -> API-based (like enrich_shodan.py)
                           Input: triage_candidates.csv
                           Output: virustotal_intelligence.csv

[enrich_phishtank.py]   -> Bulk download (like enrich_opensanctions.py)
                           Input: dea_domains.csv
                           Output: phishtank_matches.csv
```

## VirusTotal Module

### API

- Endpoint: `GET https://www.virustotal.com/api/v3/domains/{domain}`
- Auth: `x-apikey: {VT_API_Key}` header
- Free tier: 4 requests/minute, 500 requests/day

### Rate Limiting & Budget

- Rate limiter: 4 requests/minute (15-second intervals), thread-safe `RateLimiter` class
- Budget: `--budget 500` CLI flag (default), enforced via `CreditBudget` singleton from `shodan_utils.py`
- When budget exhausted: stop querying, remaining domains get empty columns

### Caching

- `ShodanCache` at `data/.vt_cache/cache.db`
- TTL: 7 days
- Cache key format: `vt:{domain}`
- 404 (unknown domain) cached as empty dict to avoid re-querying

### Output Columns

| Column | Source in VT Response | Example |
|---|---|---|
| `vt_malicious_count` | `attributes.last_analysis_stats.malicious` | `5` |
| `vt_total_engines` | sum of all `last_analysis_stats` values | `87` |
| `vt_reputation` | `attributes.reputation` | `-42` |
| `vt_last_analysis_date` | `attributes.last_analysis_date` (epoch → YYYY-MM-DD) | `2026-02-20` |

### Error Handling

| Scenario | Action |
|---|---|
| 404 Not Found | Cache empty result, continue |
| 429 Rate Limited | `@retry` with exponential backoff (3 attempts) |
| 401 Unauthorized | Log error, abort run |
| Network error | `@retry`, then skip domain |
| Budget exhausted | Stop querying, fill remaining with empty columns |

### CLI

```bash
python scripts/enrich_virustotal.py \
    --input data/triage_candidates.csv \
    --output data/virustotal_intelligence.csv \
    --budget 500 \
    --limit 500
```

## PhishTank & URLhaus Module

### Datasets

| Feed | URL | Format | Size |
|---|---|---|---|
| PhishTank | `http://data.phishtank.com/data/online-valid.csv.gz` | Gzipped CSV | ~15 MB |
| URLhaus | `https://urlhaus.abuse.ch/downloads/csv/` | CSV with `#` comment header | ~5 MB |

### Domain Extraction

Both feeds contain full URLs. Domain extraction via `urllib.parse.urlparse(url).netloc.lower()`:
- Strips scheme, path, query, fragment
- Strips port numbers (`:8080`)
- Lowercases for consistent matching
- Builds a `set()` of known-bad domains (O(1) membership test)

### Cross-Reference Strategy

1. Download both feeds (with 24h cache)
2. Extract unique domains from all URLs → `bad_domains: set`
3. Load `dea_domains.csv` (single `domain` column, ~25K domains)
4. For each domain: `if domain in bad_domains` → match
5. Write matches to `data/phishtank_matches.csv`

No fuzzy matching needed — this is exact domain-level membership testing.

### Download Caching

- Cache DB: `data/.phishtank_cache/cache.db`
- TTL: 24 hours (both feeds update frequently)
- `_dataset_meta` key with `download_timestamp` (same pattern as OpenSanctions/ICIJ)
- Raw CSV content stored in cache to avoid re-downloading

### Output Columns

| Column | Description | Example |
|---|---|---|
| `domain` | The matched domain | `evil-example.com` |
| `phishtank_match` | Boolean flag | `True` or empty |
| `phishtank_url` | Original phishing URL from feed | `http://evil-example.com/login` |
| `urlhaus_match` | Boolean flag | `True` or empty |
| `urlhaus_threat` | URLhaus threat type | `malware_download` or empty |

### CLI

```bash
python scripts/enrich_phishtank.py \
    --input data/dea_domains.csv \
    --output data/phishtank_matches.csv
```

## Fingerprint Engine Integration

No engine code changes needed. Add two modifiers to all 7 fingerprint YAML files:

```yaml
confidence_modifiers:
  - field: vt_malicious_count
    match_type: range
    value: "3-100"
    delta: 20          # 3+ VT engines flag domain as malicious

  - field: phishtank_match
    match_type: exact
    value: "True"
    delta: 15          # domain found in active phishing/malware feed
```

**Rationale:**
- `+20` for VT malicious count >= 3 is aggressive — multiple engines independently flagging is strong signal
- `+15` for PhishTank/URLhaus match is meaningful — active feeds are credible but may have false positives on shared hosting

## Pipeline Integration

Position in `update_intelligence.yml`:

```
[Triage Domains]        <- triage_domains.py
[Shodan Enrichment]     <- enrich_shodan.py (existing)
[VirusTotal Enrichment] <- NEW: enrich_virustotal.py
[PhishTank/URLhaus]     <- NEW: enrich_phishtank.py
[Technical & Pivot]     <- enrich_technical.py (existing)
```

Both steps: `continue-on-error: true`, `timeout-minutes: 30`.

VT step gated behind secret check:
```yaml
- name: VirusTotal Enrichment
  timeout-minutes: 30
  continue-on-error: true
  env:
    VT_API_KEY: ${{ secrets.VT_API_Key }}
  run: |
    if [ -n "$VT_API_KEY" ]; then
       python scripts/enrich_virustotal.py --input data/triage_candidates.csv \
         --output data/virustotal_intelligence.csv --budget 500 --limit 500
    fi
    cp data/virustotal_intelligence.csv docs/data/ || true
```

PhishTank step has no API key requirement (public bulk downloads):
```yaml
- name: PhishTank & URLhaus Feed Matching
  timeout-minutes: 30
  continue-on-error: true
  run: |
    python scripts/enrich_phishtank.py --input data/dea_domains.csv \
      --output data/phishtank_matches.csv
    cp data/phishtank_matches.csv docs/data/ || true
```

## Config Changes

Add to `config/defaults.yaml`:
```yaml
virustotal:
  budget_default: 500
  rate_limit_rpm: 4
  cache_ttl_days: 7
```

Add to `.gitignore`:
```
data/.vt_cache/
data/.phishtank_cache/
```

## Dependencies

No new packages needed. Uses:
- `requests` (already in requirements.txt)
- `ShodanCache`, `CreditBudget` from `scripts/shodan_utils.py`
- `@retry` from `scripts/shared/retry.py`
- `gzip` (Python stdlib) for PhishTank decompression
- `urllib.parse` (Python stdlib) for domain extraction
- `datetime` (Python stdlib) for epoch conversion

## Testing Strategy

### tests/test_virustotal.py (~10 tests)

| Group | Tests | Coverage |
|---|---|---|
| API response parsing | 2 | Parse VT v3 domain response, handle missing fields |
| Rate limiting | 1 | Verify 4/min throttle respects interval |
| Budget enforcement | 2 | Budget exhausted stops queries, budget tracks spend |
| Cache behavior | 2 | Cache miss triggers API call, cache hit skips |
| Error handling | 2 | 404 unknown domain cached, 429 triggers retry |
| Modifier math | 1 | vt_malicious_count range 3-100 applies +20 delta |

### tests/test_phishtank.py (~8 tests)

| Group | Tests | Coverage |
|---|---|---|
| URL domain extraction | 2 | Extract domain from URL, handle edge cases (ports, paths) |
| PhishTank CSV parsing | 1 | Parse gzipped CSV format |
| URLhaus CSV parsing | 1 | Parse comment-header CSV format |
| Cross-reference matching | 2 | Domain found in feed, domain not found |
| Download caching | 1 | Respects 24h TTL |
| Modifier math | 1 | phishtank_match exact "True" applies +15 delta |

## Error Handling

- Download failure: `@retry` 3 attempts, then log warning, skip enrichment, continue pipeline
- Corrupt/empty CSV: log error, skip feed, continue
- VT API key missing: log warning, skip VT enrichment entirely
- PhishTank 403 (IP not whitelisted): fall back to URLhaus only, log warning
