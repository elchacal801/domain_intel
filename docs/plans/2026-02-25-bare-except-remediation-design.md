# Design: Remediate Bare `except:` Blocks

**Date:** 2026-02-25
**Phase:** FLAME + domain_intel Master Plan — Phase 1 (Tech Debt)
**Scope:** 6 bare `except:` blocks across 5 pipeline scripts

## Reference Pattern

`scripts/shared/retry.py` establishes the project convention: catch **specific exception tuples**, log with context via `logging.error()`/`logging.warning()`, and either retry or return sensible defaults.

## Analysis

### Block 1: `scripts/clean_data.py:127`

```python
# BEFORE
try:
    idx = headers.index(asn_col)
    headers.insert(idx + 1, name_col)
except:
    headers.append(name_col)
```

- **Possible exceptions:** `list.index()` raises `ValueError` if element not found. `list.insert()` cannot fail after a successful `index()`.
- **Fix:** `except ValueError:`
- **Severity:** `logging.warning()` — graceful fallback (append instead of insert-after)
- **Propagation:** Swallow. Existing behavior preserved.

### Block 2: `scripts/enrich_pivot.py:37`

```python
# BEFORE
try:
    with open(HISTORY_FILE, 'r') as f:
        return set(json.load(f))
except:
    return set()
```

- **Possible exceptions:** `json.JSONDecodeError` (corrupt/empty file), `TypeError` (valid JSON but not iterable for `set()`), `OSError` (permission/disk).
- **Fix:** `except (json.JSONDecodeError, TypeError, OSError) as e:`
- **Severity:** `logging.warning()` — empty set fallback forces re-query of all emails.
- **Propagation:** Swallow. Existing behavior preserved.
- **Note:** File needs `import logging` and logger setup added.

### Block 3: `scripts/openclaw_scan.py:275`

```python
# BEFORE
try:
    first = datetime.fromisoformat(row['first_seen'])
    last = datetime.fromisoformat(row['last_seen'])
    delta = (last - first).days
    row['days_exposed'] = delta
except:
    pass
```

- **Possible exceptions:** `ValueError` (malformed ISO date), `KeyError` (missing column in CSV row), `TypeError` (None value).
- **Fix:** `except (ValueError, KeyError, TypeError) as e:`
- **Severity:** `logging.warning()` — one row's calculation skipped.
- **Propagation:** Swallow. Existing behavior preserved. Logger already exists as `log`.

### Block 4: `scripts/visual_fingerprint.py:104`

```python
# BEFORE
try:
    await page.goto(url, timeout=10000, wait_until="domcontentloaded")
    await asyncio.sleep(1)
except:
    # Falls through to HTTPS retry
```

- **Possible exceptions:** `playwright.async_api.Error` (base class catches TimeoutError + navigation failures).
- **Fix:** `except playwright.async_api.Error as e:`
- **Severity:** `logging.debug()` — HTTP-to-HTTPS fallback is expected behavior.
- **Propagation:** Swallow. Existing behavior preserved (falls through to HTTPS attempt).
- **Note:** Import `Error` from `playwright.async_api`.

### Block 5: `scripts/visual_fingerprint.py:110`

```python
# BEFORE
try:
    url = f"https://{domain}"
    await page.goto(url, timeout=10000, wait_until="domcontentloaded")
    await asyncio.sleep(1)
except:
    return None
```

- **Possible exceptions:** Same as Block 4 — `playwright.async_api.Error`.
- **Fix:** `except playwright.async_api.Error as e:`
- **Severity:** `logging.warning()` — both HTTP and HTTPS failed, domain unreachable.
- **Propagation:** Swallow. Returns `None` (existing behavior).

### Block 6: `scripts/test_shodan_capabilities.py:26`

```python
# BEFORE
try:
    info = api.info()
    ...
except:
    print("Could not fetch plan info.")
```

- **Possible exceptions:** `shodan.APIError` (auth/API failure), `requests.RequestException` (transport error).
- **Fix:** `except (shodan.APIError, requests.RequestException) as e:`
- **Severity:** `print()` with error detail — this is a diagnostic script, not pipeline code.
- **Propagation:** Swallow. Existing behavior preserved.
- **Note:** Add `import requests` at top.

## Principles

1. Catch the **narrowest possible exception set** — only what the code can actually raise.
2. Log at the **right severity** — `warning` for unexpected degradation, `debug` for expected fallbacks.
3. **Preserve existing behavior exactly** — same return values, same control flow.
4. Add `import logging` only where missing.
