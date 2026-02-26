# Design: GLEIF Entity Legitimacy Verification Module

**Date:** 2026-02-25
**Phase:** FLAME + domain_intel Master Plan — Phase 1
**Issue:** Integrate GLEIF API for Entity Verification

## Purpose

Query the Global Legal Entity Identifier Foundation (GLEIF) API to verify if a domain's registrant is a known, active business. Adds entity verification signals to the enrichment pipeline that the fingerprint engine can use as confidence modifiers.

## Architecture: Standalone Enrichment Script (Approach 1)

`scripts/enrich_gleif.py` reads enriched domain data, deduplicates unique org names, queries the GLEIF REST API with caching and rate limiting, and appends 5 new columns. Reuses the existing `ShodanCache` class for SQLite caching.

## RDAP Registrant Extraction

Extend `scripts/enrich_reputation.py` to extract `registrant_org` from the RDAP response JSON. The RDAP `entities` array contains entries with `roles` (e.g., `"registrant"`) and `vcardArray` data with organization/name fields.

```python
registrant_org = ""
for entity in rdap_data.get("entities", []):
    if "registrant" in entity.get("roles", []):
        for vcard in entity.get("vcardArray", [[], []])[1]:
            if vcard[0] in ("fn", "org"):
                registrant_org = vcard[3] if len(vcard) > 3 else ""
                break
        break
```

This adds `registrant_org` as a new column in `dea_domains_probed.csv`. Many domains will be empty (privacy-protected), which is where the `ssl_org` fallback comes in.

## GLEIF Enrichment Script

### Input

`data/dea_domains_probed.csv` — uses `registrant_org` if non-empty, else `ssl_org`, else skips the domain.

### API Logic

1. Deduplicate org names (~15k domains → ~500-2000 unique orgs)
2. For each unique org, check SQLite cache (7-day TTL)
3. On cache miss, query GLEIF API:
   - Primary: `GET https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]={name}`
   - Fallback: `GET https://api.gleif.org/api/v1/lei-records?filter[fulltext]={name}` if exact returns 0 results
4. Extract from first result: `lei`, `entity.status`, `entity.jurisdiction`, `entity.legalName`, parent info
5. Cache result (including "no LEI found" to avoid re-querying)
6. Join results back to domain rows by org name

### Output Columns

| Column | Description | Example |
|---|---|---|
| `gleif_lei` | 20-char LEI code | `7ZW8QJWVPR4P1J1KBDYI` or empty |
| `gleif_status` | Entity status | `ACTIVE`, `LAPSED`, `RETIRED`, `MERGED`, or empty |
| `gleif_legal_name` | Official legal name from GLEIF | `Apple Inc.` or empty |
| `gleif_jurisdiction` | 2-letter country of legal registration | `US`, `GB`, or empty |
| `gleif_has_parent` | Whether entity has a parent | `True`, `False`, or empty |

### Caching

- Reuse `ShodanCache` from `scripts/shodan_utils.py` with dedicated path: `data/.gleif_cache/cache.db`
- Cache key: `"org:{normalized_org_name}"` (lowercased, stripped)
- TTL: 7 days (`max_age_days=7`)
- "No LEI found" results are cached as `{"gleif_lei": "", "gleif_status": ""}` to avoid re-querying

### Rate Limiting

- 0.5-second delay between requests (2 RPS)
- Sequential processing (no threading for API calls — deduplication keeps query count manageable)
- `time.sleep(0.5)` in the query loop, after cache check
- Use `@retry` from `shared/retry.py` for transient HTTP failures

### CLI

```
python scripts/enrich_gleif.py \
  --input data/dea_domains_probed.csv \
  --output data/dea_domains_probed.csv \
  --limit 0
```

## Fingerprint Engine Integration

No engine code changes needed — the fingerprint engine already handles any CSV column as a modifier field. Add `gleif_status` and `gleif_lei` modifiers to all 7 existing fingerprint YAML files:

```yaml
confidence_modifiers:
  # ... existing modifiers ...
  - field: gleif_status
    match_type: exact
    value: "ACTIVE"
    delta: -15        # confirmed legitimate entity reduces suspicion

  - field: gleif_lei
    match_type: exact
    value: ""
    delta: 10         # no LEI found mildly increases suspicion
```

**Rationale:**
- `-15` for ACTIVE is strong enough to meaningfully affect scoring (e.g., FP-0005 base 55 drops to 40) without neutralizing a match
- `+10` for missing LEI is mild — absence of evidence is weak evidence, only meaningful combined with other indicators

## Pipeline Integration

Position in `update_intelligence.yml`:

```
[Data Hygiene]              ← clean_data.py, enrich_asns.py
[GLEIF Entity Verification] ← NEW: enrich_gleif.py
[Fingerprint Matching]      ← match_fingerprints.py (now has gleif fields)
[Triage]                    ← triage_domains.py
```

## Testing Strategy

`tests/test_gleif.py` — 11+ test functions, pytest, mocked HTTP responses.

| Group | Tests | Coverage |
|---|---|---|
| API response parsing | 3 | Active LEI, lapsed LEI, no results |
| Cache behavior | 3 | Miss triggers API, hit skips API, expired triggers re-query |
| Org name extraction | 2 | Prefers registrant_org over ssl_org, handles both empty |
| Rate limiting | 1 | Sequential calls respect 0.5s delay |
| Modifier math | 2 | ACTIVE → -15, empty LEI → +10 |

## Error Handling

- GLEIF API returns non-200: `log.warning()`, cache empty result, continue
- GLEIF API timeout: `@retry` with 3 attempts, exponential backoff
- Malformed JSON response: `log.error()`, skip org, continue
- Missing registrant_org AND ssl_org: skip domain (no org to look up)
- SQLite cache corruption: `log.error()`, fall through to API call
- Follow `shared/retry.py` pattern: specific exceptions, structured logging
