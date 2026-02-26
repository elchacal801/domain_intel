# Design: OpenSanctions & ICIJ OffshoreLeaks Entity Screening

**Date:** 2026-02-26
**Phase:** FLAME + domain_intel Master Plan — Phase 1
**Issue:** Integrate OpenSanctions & ICIJ Entity Screening

## Purpose

Fuzzy-match domain registrant organizations against global sanctions watchlists (OpenSanctions) and offshore leak databases (ICIJ OffshoreLeaks). Adds entity screening signals to the enrichment pipeline that the fingerprint engine uses as confidence modifiers.

## Architecture: Bulk Download + Local Fuzzy Match

Both `scripts/enrich_opensanctions.py` and `scripts/enrich_icij.py` follow the established `enrich_gleif.py` pattern: download bulk dataset, load into SQLite FTS table, fuzzy-match against `registrant_org`/`ssl_org`, append output columns. No per-domain API calls — all matching happens locally.

```
[enrich_reputation.py]      -> registrant_org, ssl_org
[enrich_gleif.py]           -> gleif_lei, gleif_status, ...
[enrich_opensanctions.py]   -> os_match_score, os_entity_type, os_dataset, os_entity_id
[enrich_icij.py]            -> icij_match_score, icij_entity_match, icij_dataset, icij_jurisdiction
[match_fingerprints.py]     -> uses all columns above as confidence modifiers
```

## Matching Strategy: FTS + Levenshtein Hybrid

Pure Levenshtein against 1.29M names is O(n) per query — too slow. Instead:

1. Load entity names into a SQLite FTS5 virtual table
2. For each unique org name, query FTS for prefix/token candidates (~10-50 results)
3. Score candidates with `Levenshtein.ratio()` (already in requirements.txt)
4. Keep best match if score >= 0.7; discard otherwise
5. Cache per-org results in ShodanCache (key-value) to skip re-matching on subsequent runs

Match scores stored as **integer percentages 0-100** (not floats) so the fingerprint engine's existing `range` match_type works without code changes.

## OpenSanctions Module

### Dataset

- URL: `https://data.opensanctions.org/datasets/latest/default/targets.simple.csv`
- Size: ~459 MB, ~1.29M rows
- Cache: `data/.opensanctions_cache/cache.db`
- TTL: **24 hours** (sanctions lists update frequently)

### Dataset Schema (targets.simple.csv)

Key columns used: `id`, `schema` (Company/Person/LegalEntity), `name`, `aliases` (semicolon-delimited), `dataset` (semicolon-delimited source lists).

Aliases are expanded — each alias inserted as a separate FTS row pointing to the same entity_id.

### Output Columns

| Column | Description | Example |
|---|---|---|
| `os_match_score` | Levenshtein match score (0-100) | `85` or empty |
| `os_entity_type` | Entity schema from OpenSanctions | `Company`, `Person`, or empty |
| `os_dataset` | Source sanctions list(s) | `US OFAC SDN List` or empty |
| `os_entity_id` | OpenSanctions entity ID | `NK-223CQDBzp8MRkdJMDiqXn3` or empty |

## ICIJ OffshoreLeaks Module

### Dataset

- URL: `https://offshoreleaks-data.icij.org/offshoreleaks/csv/full-oldb.LATEST.zip`
- Contains separate CSVs per node type; we use **entities** (companies/trusts) and **officers** (individuals) from all 4 datasets (Panama Papers, Paradise Papers, Pandora Papers, Offshore Leaks)
- Cache: `data/.icij_cache/cache.db`
- TTL: **7 days** (ICIJ data updates infrequently)

### Output Columns

| Column | Description | Example |
|---|---|---|
| `icij_match_score` | Levenshtein match score (0-100) | `82` or empty |
| `icij_entity_match` | Boolean flag for fingerprint modifier | `True` or empty |
| `icij_dataset` | Source leak dataset | `Panama Papers` or empty |
| `icij_jurisdiction` | Jurisdiction from ICIJ data | `Panama` or empty |

## Dataset Download & Storage

### Download Flow

1. Check SQLite cache for `_dataset_meta` key with `download_timestamp`
2. If missing or expired (24h OpenSanctions, 7d ICIJ), download fresh
3. Download to temp file with `requests.get(url, stream=True)` + `@retry`
4. Load into SQLite FTS tables, store `_dataset_meta` timestamp

### SQLite FTS Table Schema

```sql
CREATE VIRTUAL TABLE IF NOT EXISTS entity_names USING fts5(
    name,           -- primary name (lowercased)
    entity_id,      -- NK-xxx or ICIJ node_id
    entity_type,    -- Company/Person/LegalEntity
    dataset,        -- source dataset(s)
    jurisdiction    -- country codes (ICIJ) or empty (OpenSanctions)
);
```

Both the FTS table and the per-org match cache (via ShodanCache) live in the same SQLite file.

### Caching

- **ShodanCache** for per-org match results: key `"org:{normalized_name}"`, TTL matches dataset TTL
- "No match found" results cached as empty dict to avoid re-querying
- Dataset metadata cached with download timestamp for TTL checks

## Fingerprint Engine Integration

No engine code changes needed. Add two modifiers to all 7 fingerprint YAML files:

```yaml
confidence_modifiers:
  - field: os_match_score
    match_type: range
    value: "70-100"
    delta: 20          # registrant matches sanctioned entity

  - field: icij_entity_match
    match_type: exact
    value: "True"
    delta: 15          # registrant found in offshore leaks
```

**Rationale:**
- `+20` for sanctions match is aggressive — a registrant on OFAC/EU sanctions lists is a strong signal
- `+15` for offshore leaks is meaningful but weaker — offshore entities aren't inherently malicious, just higher risk

## Pipeline Integration

Position in `update_intelligence.yml`:

```
[Data Hygiene]              <- clean_data.py, enrich_asns.py
[GLEIF Entity Verification] <- enrich_gleif.py
[OpenSanctions Screening]   <- NEW: enrich_opensanctions.py
[ICIJ OffshoreLeaks]        <- NEW: enrich_icij.py
[Fingerprint Matching]      <- match_fingerprints.py
```

Both steps: `continue-on-error: true`, `timeout-minutes: 30`.

## Error Handling

- Download failure: `@retry` 3 attempts, then log warning, skip enrichment, continue pipeline
- Corrupt/empty CSV: log error, skip enrichment, continue
- FTS table build failure: log error, fall through — domains get empty columns
- Malformed rows in downloaded data: skip row, log count at end
- Match with no org name: skip domain (same as GLEIF pattern)

## Testing Strategy

### tests/test_opensanctions.py (~10 tests)

| Group | Tests | Coverage |
|---|---|---|
| FTS loading | 2 | Load sample CSV into FTS, verify row count and alias expansion |
| Fuzzy matching | 3 | Exact match (score=100), close match (score>=70), no match (score<70) |
| Cache behavior | 2 | Cache miss triggers match, cache hit skips match |
| Dataset download | 1 | Mock download, verify FTS table populated |
| Org name extraction | 2 | Prefers registrant_org, handles empty |

### tests/test_icij.py (~8 tests)

| Group | Tests | Coverage |
|---|---|---|
| ZIP extraction | 1 | Extract entity + officer CSVs from mock ZIP |
| FTS loading | 2 | Load entities and officers into FTS, verify counts |
| Fuzzy matching | 3 | Exact match, close match, no match |
| Cache behavior | 2 | Cache miss/hit behavior |

### Modifier tests (in existing test files)

| Group | Tests | Coverage |
|---|---|---|
| os_match_score range | 1 | Score 85 in range 70-100 applies +20 delta |
| icij_entity_match exact | 1 | "True" applies +15 delta |

## Dependencies

No new packages needed. Uses:
- `python-Levenshtein` (already in requirements.txt)
- `requests` (already in requirements.txt)
- `sqlite3` with FTS5 (Python stdlib)
- `ShodanCache` from `scripts/shodan_utils.py`
- `@retry` from `scripts/shared/retry.py`

## Future: nomenklatura Deep Analysis

A future post-triage script could use `nomenklatura` + FollowTheMoney for graph-based entity resolution on flagged domains only. This would enable cross-entity relationship traversal (beneficial owners, shell company networks) but requires heavy dependencies and is better suited as a targeted deep-dive tool rather than a daily pipeline step.
