# SecurityTrails Manual Investigation Tool — Design Document

**Date:** 2026-02-26
**Status:** Approved

## Problem Statement

SecurityTrails provides historical DNS and WHOIS data invaluable for domain investigations, but the free tier allows only 50 API queries total per 30-day rolling window. This makes it unsuitable for automated bulk enrichment in the CI pipeline. Instead, it must be built as a highly guarded, manual-only investigation tool with a persistent circuit breaker that absolutely prevents exceeding the quota.

## Architecture

Single-domain CLI tool (`scripts/enrich_securitytrails.py`) backed by a persistent SQLite quota tracker (`scripts/shared/api_budget.py`). Queries SecurityTrails API v1 for historical DNS (A, MX, NS) and historical WHOIS. 4 API calls per full domain investigation. Hard circuit breaker at 50 queries per 30-day rolling window. Results cached in SQLite with 30-day TTL — cached results do NOT consume quota.

**Deliberately excluded from CI pipeline.** This script never appears in `.github/workflows/update_intelligence.yml`.

## Circuit Breaker: `scripts/shared/api_budget.py`

### Why a New Module

The existing `CreditBudget` in `shodan_utils.py` is ephemeral (per-run, resets on each invocation). SecurityTrails needs **persistent** 30-day rolling window tracking in SQLite — a fundamentally different pattern. A dedicated module keeps it clean and reusable for future quota-limited APIs.

### Class: `PersistentQuotaTracker`

```python
PersistentQuotaTracker(db_path, max_queries, window_days)
├── get_usage() -> int           # COUNT(*) WHERE ts > now - window_days
├── get_remaining() -> int       # max_queries - get_usage()
├── can_spend(cost) -> bool      # get_remaining() >= cost
├── record_usage(api_name, domain, cost=1)  # INSERT row with timestamp
├── abort_if_exceeded(cost)      # raises SystemExit if can_spend is False
└── close()                      # close SQLite connection
```

### SQLite Schema

```sql
CREATE TABLE IF NOT EXISTS api_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_name TEXT NOT NULL,
    domain TEXT NOT NULL,
    cost INTEGER NOT NULL DEFAULT 1,
    timestamp REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_api_usage_ts ON api_usage(timestamp);
```

### Pre-Flight Check

Before making ANY network request, the script calls `tracker.abort_if_exceeded(4)` to verify at least 4 queries remain for a full investigation. If not, it prints remaining budget and exits with code 1. This is the hard gate — no network request is ever made if budget is insufficient.

### Query Cost Model

1 query = 1 API call. A full domain investigation costs 4 queries (A + MX + NS + WHOIS). The tracker records each API call individually, giving precise per-call accounting.

## CLI Interface

```
python scripts/enrich_securitytrails.py --domain evil-example.com [--save] [--budget-check]
```

| Flag | Required | Purpose |
|------|----------|---------|
| `--domain` | Yes | Single domain to investigate |
| `--save` | No | Append results to `data/manual_investigations.csv` |
| `--budget-check` | No | Print remaining quota and exit (no API calls) |

**No `--input` CSV mode. No batch processing.** This is deliberately single-domain-only to force the analyst to be intentional about every query.

## API Calls (4 per Investigation)

All calls use `GET` with `apikey` query parameter. Base URL: `https://api.securitytrails.com/v1/`

| # | Endpoint | Returns |
|---|----------|---------|
| 1 | `/history/{domain}/dns/a` | Historical A record IPs with first/last seen dates |
| 2 | `/history/{domain}/dns/mx` | Historical MX records with change dates |
| 3 | `/history/{domain}/dns/ns` | Historical NS records with change dates |
| 4 | `/history/{domain}/whois` | WHOIS snapshots with registrar, contacts, dates |

Each call is individually recorded in the quota tracker. If any call fails (network error, 429, etc.), subsequent calls are still attempted — partial results are useful.

API key loaded from environment variable `ST_API_KEY` via `load_dotenv()`.

## Output Columns

| Column | Type | Source | Description |
|--------|------|--------|-------------|
| `st_dns_history_count` | int | A record history | Count of unique A record IPs |
| `st_registrar_changes` | int | WHOIS history | Count of distinct registrars |
| `st_mx_history` | str | MX record history | Semicolon-joined MX providers |
| `st_first_seen` | str | Earliest DNS record | ISO date (YYYY-MM-DD) |
| `st_mx_change_date` | str | MX record history | Most recent MX change date |

## Console Output Format

```
═══════════════════════════════════════════════
 SecurityTrails Investigation: evil-example.com
═══════════════════════════════════════════════
 Budget: 46/50 remaining (4 used this investigation)

 DNS History (A Records): 12 unique IPs
 ─────────────────────────────
   2019-03-15  1.2.3.4       (first seen)
   2024-06-01  5.6.7.8
   2025-11-20  9.10.11.12    (current)

 MX History: 3 changes
 ─────────────────────────────
   2019-03-15  google.com
   2023-01-10  protonmail.ch
   2025-11-20  temp-mail-pro.com

 NS History: 2 changes
 ─────────────────────────────
   2019-03-15  ns1.registrar-servers.com
   2025-10-01  ns1.cprapid.com

 WHOIS History: 3 registrar changes
 ─────────────────────────────
   2019-03-15  GoDaddy (John Smith)
   2023-06-01  Namecheap (REDACTED)
   2025-09-15  PDR Ltd (Privacy Protected)
═══════════════════════════════════════════════
```

## Caching

Reuse `ShodanCache` (the existing generic SQLite KV cache) at `data/.securitytrails_cache/cache.db` with 30-day TTL. When a domain has cached results:
- Cache hit skips all API calls for that domain
- No quota consumed
- Stale cache (>30 days) triggers fresh API calls

Cache key format: `st:{domain}:{endpoint}` (e.g., `st:evil.com:dns/a`).

## Fingerprint Hooks

Add `st_` modifiers to FP-0001 and FP-0007 as **optional confidence modifiers**. No fingerprint requires them — they only fire if the `st_` fields happen to be present from a manual investigation.

```yaml
# Added to relevant fingerprints
confidence_modifiers:
  - field: st_registrar_changes
    match_type: range
    value: "3-100"
    delta: 10
  - field: st_dns_history_count
    match_type: range
    value: "10-1000"
    delta: 5
```

The fingerprint engine already handles missing fields gracefully (empty field = no match = no delta applied).

## Configuration

Add to `config/defaults.yaml`:

```yaml
securitytrails:
  max_queries_30d: 50
  cache_ttl_days: 30
```

## Files Changed

| File | Action | Description |
|------|--------|-------------|
| `scripts/shared/api_budget.py` | Create | PersistentQuotaTracker with SQLite-backed 30-day rolling window |
| `scripts/enrich_securitytrails.py` | Create | Manual single-domain investigation tool |
| `tests/test_securitytrails.py` | Create | Circuit breaker tests + enrichment tests |
| `config/defaults.yaml` | Modify | Add securitytrails section |
| `config/fingerprints/FP-0001-*.yaml` | Modify | Add st_registrar_changes and st_dns_history_count modifiers |
| `config/fingerprints/FP-0007-*.yaml` | Modify | Add st_registrar_changes and st_dns_history_count modifiers |
| `.gitignore` | Modify | Add `data/.securitytrails_cache/` |
| `data/README.md` | Modify | Document manual-only constraint |

## Out of Scope

- Bulk CSV processing (deliberately excluded)
- CI pipeline integration (free tier cannot support it)
- SOA/TXT/AAAA historical queries (budget optimization: 4 calls covers core signals)
- Reverse DNS / IP neighbors (separate investigation workflow)
- Automatic re-investigation on cache expiry (analyst must manually re-run)
