# VPN Relay LogScale Lookup + Seed Refresh — Design

**Date:** 2026-07-07
**Status:** Approved (pending spec review)

## Problem

Two related goals:

1. **Seed refresh** — the manual quarterly/annual VPN seeds were last refreshed 2026-05-15 (Astrill: 2024). Refresh the seeds that are feasible on this machine so the pipeline collects current data.
2. **Sub-10 MB relay CSV** — `data/vpn_relay_ips.csv` is **13.9 MB** (51,661 rows × 23 columns). It is uploaded to CrowdStrike/Falcon **LogScale as a lookup file**, but exceeds LogScale's practical upload limit. We need a lean, match-focused version under 10 MB, produced automatically each run.

The size is dominated by verbose, highly repeated text columns (`threat_relevance`, `collection_method`, `source`, `hostname`, `city`, …) that LogScale detection rules do not join on.

## Part A — Seed Refresh (operational)

Documented in `docs/vpn-ip-intel-operations.md`. Feasibility on this machine (checked 2026-07-07):

| Seed | Source | Feasible now | Action |
|------|--------|--------------|--------|
| ExpressVPN cache | `C:\Program Files\ExpressVPN\data\data.json` (present, fresh) | Yes | Copy → `data/vpn_seeds/expressvpn_data.json` |
| ProtonVPN cache | `%LOCALAPPDATA%\Proton\Proton VPN\Storage\Servers.<hash>.bin` (present) | Yes | Copy → `data/vpn_seeds/protonvpn/Servers.current.bin` |
| Mullvad exit probe | `scripts/mullvad_exit_probe.py` + active Mullvad WireGuard | No — currently Disconnected | User connects Mullvad, then run probe |
| Astrill (Spur) | Spur Intelligence export (annual) | No — external | User obtains → `data/vpn_seeds/spur_astrill_2026.txt` |

The 17 fully-automated providers refresh every run with no manual action.

**Sequencing decision:** the ExpressVPN + ProtonVPN seed copies land first, then the lookup feature (Part B) is implemented, then the pipeline is run **locally once** to regenerate `vpn_relay_ips.csv` (fresh seeds) *and* produce `vpn_relay_lookup.csv` in the same run. CI picks up subsequent daily refreshes. This avoids running the pipeline twice.

## Part B — LogScale Lookup File (code feature)

### Output

New file `data/vpn_relay_lookup.csv`, written every run alongside the master CSV.

- **Row scope:** all rows — exact-IP + CIDR (prefix/egress-inferred) + active *and* inactive. No filtering.
- **Measured size:** 6.83 MB / 51,661 rows (3.17 MB headroom under 10 MB).

### Schema (13 columns)

```
ip, prefix, provider, asn, asn_name, source_date,
score_prehire, tier_prehire, score_posthire, tier_posthire,
first_seen, last_seen, active
```

Data fact validated on the current master CSV: the row set is a **clean partition** — every empty-`ip` row (3,313) has a populated `prefix`, and no exact-`ip` row has a `prefix`. So each row keys on exactly one of `ip` or `prefix`; LogScale rules select the key by which column is non-empty.

### Integration (`scripts/vpn_ip_intel.py`)

Mirror the existing legacy-CSV pattern (the master write at line 1852 followed by the derived `vpn_exit_ips.csv` write at lines 1855–1858):

1. Add a module constant `LOOKUP_FIELDS` = the 13 columns above.
2. Parametrize the writer: `write_csv(nodes, path, fields=FIELDS)` (default preserves current behavior; `extrasaction="ignore"` already drops unlisted keys — it is a pure column projection, no new computation).
3. After the master write, emit the lookup by deriving the path:
   `lookup_path = output.replace("vpn_relay_ips", "vpn_relay_lookup")` — guarded by the same `if "vpn_relay_ips" in output` check, writing **all** `all_nodes_with_prefix` rows (not the active-only subset used for legacy/per-provider CSVs).

### CI

The daily `update_intelligence.yml` run must stage and commit the new `data/vpn_relay_lookup.csv`. Confirm the exact commit step during planning and add the file if the staging is path-specific rather than a broad `git add data/`.

### Tests

Add to the existing VPN test suite:

- Lookup header equals exactly the 13 `LOOKUP_FIELDS`, in order.
- Row-count parity: lookup row count == master row count (all rows carried through).
- Column projection correctness: a sampled row's 13 values match the master row.
- **Size guard:** lookup file size is under 10 MB, and a warning threshold at 9 MB (documents the growth risk below).

### Deferred (out of scope, noted)

- **Retention cap.** Inactive rows accumulate indefinitely (temporal history is never pruned), so the lookup grows ~monthly. At 6.83 MB this is fine. The 9 MB warn guard surfaces the problem early; a retention policy (drop rows inactive > N days) can be added later if it approaches the limit. **Deferred by decision.**

## Non-goals

- No change to the master `vpn_relay_ips.csv` schema or the legacy `vpn_exit_ips.csv`.
- No compression or file splitting (column projection alone clears the limit).
- No CIDR-expansion of prefix rows into member IPs — prefixes are carried as-is for LogScale subnet matching.
