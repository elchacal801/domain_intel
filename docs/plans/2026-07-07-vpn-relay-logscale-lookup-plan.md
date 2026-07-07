# VPN Relay LogScale Lookup + Seed Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an auto-generated, sub-10 MB `data/vpn_relay_lookup.csv` (lean 13-column projection of the master relay CSV) for LogScale upload, and refresh the feasible VPN seeds.

**Architecture:** A pure column-projection of the existing in-memory node set, written next to the master CSV by mirroring the existing legacy-CSV write pattern in `scripts/vpn_ip_intel.py`. No new data is computed. A small extracted helper (`write_lookup_csv`) keeps the emission unit-testable. Seed refresh is operational (copy local app caches). One local pipeline run produces both the refreshed master and the new lookup.

**Tech Stack:** Python 3, stdlib `csv`, pytest.

**Design doc:** `docs/plans/2026-07-07-vpn-relay-logscale-lookup-design.md`

---

### Task 0: Feature isolation + docs commit + issue

**Files:**
- Move: `docs/plans/2026-07-07-vpn-relay-logscale-lookup-design.md`, `docs/plans/2026-07-07-vpn-relay-logscale-lookup-plan.md` (from main working tree into the worktree)

- [ ] **Step 1: Create the GitHub issue**

```bash
gh issue create \
  --title "VPN relay LogScale lookup (<10MB) + quarterly seed refresh" \
  --body "Add auto-generated data/vpn_relay_lookup.csv (lean 13-col projection, all rows) for LogScale upload; refresh ExpressVPN + ProtonVPN seeds. Design: docs/plans/2026-07-07-vpn-relay-logscale-lookup-design.md"
```

- [ ] **Step 2: Create the worktree + feature branch off current main**

Run from the repo root (`C:\Users\anon\Documents\anon\repos\domain_intel`):

```bash
git worktree add .worktrees/vpn-relay-lookup -b feature/vpn-relay-logscale-lookup
```

- [ ] **Step 3: Move the design + plan docs into the worktree and commit them there**

The two doc files are currently untracked in the main working tree; move them into the worktree checkout, then commit.

```bash
mv docs/plans/2026-07-07-vpn-relay-logscale-lookup-design.md .worktrees/vpn-relay-lookup/docs/plans/
mv docs/plans/2026-07-07-vpn-relay-logscale-lookup-plan.md .worktrees/vpn-relay-lookup/docs/plans/
git -C .worktrees/vpn-relay-lookup add docs/plans/2026-07-07-vpn-relay-logscale-lookup-design.md docs/plans/2026-07-07-vpn-relay-logscale-lookup-plan.md
git -C .worktrees/vpn-relay-lookup commit -m "docs: VPN relay LogScale lookup design + plan"
```

All remaining tasks run **inside** `.worktrees/vpn-relay-lookup/`. Paths below are relative to that worktree root.

---

### Task 1: Add `LOOKUP_FIELDS` and `LOOKUP_WARN_BYTES` constants

**Files:**
- Modify: `scripts/vpn_ip_intel.py:36-43` (add constants immediately after the `FIELDS` list)
- Test: `tests/test_vpn_ip_intel.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_vpn_ip_intel.py`. First extend the import at line 12-25 to include `LOOKUP_FIELDS, LOOKUP_WARN_BYTES`, then add:

```python
class TestLogScaleLookup:
    """Lean vpn_relay_lookup.csv projection for LogScale upload."""

    def test_lookup_fields_exact_order(self):
        assert LOOKUP_FIELDS == [
            "ip", "prefix", "provider", "asn", "asn_name", "source_date",
            "score_prehire", "tier_prehire", "score_posthire", "tier_posthire",
            "first_seen", "last_seen", "active",
        ]

    def test_lookup_fields_are_subset_of_master(self):
        # Projection must never invent columns absent from the master schema.
        assert set(LOOKUP_FIELDS).issubset(set(FIELDS))

    def test_lookup_warn_threshold_under_limit(self):
        # Warn threshold must sit below the 10 MB hard limit.
        assert 0 < LOOKUP_WARN_BYTES < 10_000_000
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_vpn_ip_intel.py::TestLogScaleLookup -v`
Expected: FAIL — `ImportError: cannot import name 'LOOKUP_FIELDS'`

- [ ] **Step 3: Add the constants**

In `scripts/vpn_ip_intel.py`, immediately after the `FIELDS = [ ... ]` block (line 43), add:

```python
# Lean projection of FIELDS for the LogScale lookup file (data/vpn_relay_lookup.csv).
# Each row keys on `ip` (exact) or `prefix` (CIDR) — never both.
LOOKUP_FIELDS = [
    "ip", "prefix", "provider", "asn", "asn_name", "source_date",
    "score_prehire", "tier_prehire", "score_posthire", "tier_posthire",
    "first_seen", "last_seen", "active",
]

# Warn when the lookup approaches LogScale's 10 MB upload limit.
LOOKUP_WARN_BYTES = 9_000_000
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_vpn_ip_intel.py::TestLogScaleLookup -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add scripts/vpn_ip_intel.py tests/test_vpn_ip_intel.py
git commit -m "feat: add LOOKUP_FIELDS + LOOKUP_WARN_BYTES for LogScale lookup"
```

---

### Task 2: Parametrize `write_csv` to accept a `fields` argument

**Files:**
- Modify: `scripts/vpn_ip_intel.py:1785-1792` (`write_csv`)
- Test: `tests/test_vpn_ip_intel.py` (add to `TestLogScaleLookup`)

- [ ] **Step 1: Write the failing test**

```python
    def test_write_csv_projects_and_drops_extra_columns(self, tmp_path):
        import csv as _csv
        from vpn_ip_intel import write_csv
        # A node carrying verbose master-only columns that must be dropped.
        node = {
            "ip": "1.2.3.4", "prefix": "", "provider": "mullvad", "asn": "AS1",
            "asn_name": "Example, US", "source_date": "2026-07-07",
            "score_prehire": "8", "tier_prehire": "contextual",
            "score_posthire": "8", "tier_posthire": "contextual",
            "first_seen": "2026-06-01", "last_seen": "2026-07-07", "active": "true",
            # extras that must NOT appear in the lookup:
            "threat_relevance": "long verbose text", "hostname": "x-wg-001",
            "collection_method": "Public API", "city": "NYC",
        }
        out = tmp_path / "vpn_relay_lookup.csv"
        write_csv([node], str(out), fields=LOOKUP_FIELDS)
        with open(out, newline="", encoding="utf-8") as f:
            reader = _csv.reader(f)
            header = next(reader)
            rows = list(reader)
        assert header == LOOKUP_FIELDS
        assert len(rows) == 1
        assert rows[0][0] == "1.2.3.4"
        assert "threat_relevance" not in header and "hostname" not in header

    def test_write_csv_default_fields_unchanged(self, tmp_path):
        import csv as _csv
        from vpn_ip_intel import write_csv
        out = tmp_path / "master.csv"
        write_csv([{"ip": "1.2.3.4"}], str(out))
        with open(out, newline="", encoding="utf-8") as f:
            header = next(_csv.reader(f))
        assert header == FIELDS  # default still writes the full master schema
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_vpn_ip_intel.py::TestLogScaleLookup::test_write_csv_projects_and_drops_extra_columns -v`
Expected: FAIL — `TypeError: write_csv() got an unexpected keyword argument 'fields'`

- [ ] **Step 3: Parametrize `write_csv`**

Replace `write_csv` (lines 1785-1792) with:

```python
def write_csv(nodes: List[Dict], path: str, fields: List[str] = FIELDS) -> None:
    """Write nodes to CSV. `fields` selects and orders the columns; keys in a
    node dict that are not in `fields` are ignored (pure projection)."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(nodes)
    logger.info(f"Wrote {len(nodes)} rows to {path}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_vpn_ip_intel.py::TestLogScaleLookup -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add scripts/vpn_ip_intel.py tests/test_vpn_ip_intel.py
git commit -m "refactor: parametrize write_csv column set (default unchanged)"
```

---

### Task 3: Emit `vpn_relay_lookup.csv` from the pipeline

**Files:**
- Modify: `scripts/vpn_ip_intel.py` — add `write_lookup_csv` near `write_csv` (~line 1793), call it in `run()` after the master write (line 1852)
- Test: `tests/test_vpn_ip_intel.py` (add to `TestLogScaleLookup`)

- [ ] **Step 1: Write the failing test**

Extend the import to include `write_lookup_csv`, then add:

```python
    def _sample_nodes(self):
        # Mixed: exact-IP active, exact-IP inactive, CIDR (empty ip, has prefix).
        base = {
            "provider": "mullvad", "asn": "AS1", "asn_name": "Ex, US",
            "source_date": "2026-07-07", "score_prehire": "8", "tier_prehire": "contextual",
            "score_posthire": "8", "tier_posthire": "contextual",
            "first_seen": "2026-06-01", "last_seen": "2026-07-07",
        }
        return [
            {**base, "ip": "1.2.3.4", "prefix": "", "active": "true"},
            {**base, "ip": "5.6.7.8", "prefix": "", "active": "false"},
            {**base, "ip": "", "prefix": "9.9.9.0/24", "active": "true"},
        ]

    def test_write_lookup_derives_path_and_keeps_all_rows(self, tmp_path):
        import csv as _csv
        out = tmp_path / "vpn_relay_ips.csv"
        result = write_lookup_csv(self._sample_nodes(), str(out))
        expected = tmp_path / "vpn_relay_lookup.csv"
        assert result == str(expected)
        assert expected.exists()
        with open(expected, newline="", encoding="utf-8") as f:
            rows = list(_csv.reader(f))
        assert rows[0] == LOOKUP_FIELDS
        assert len(rows) - 1 == 3  # all rows incl. inactive + CIDR

    def test_write_lookup_noop_for_unrelated_output(self, tmp_path):
        out = tmp_path / "something_else.csv"
        assert write_lookup_csv(self._sample_nodes(), str(out)) is None

    def test_write_lookup_warns_when_large(self, tmp_path, caplog, monkeypatch):
        import logging
        monkeypatch.setattr("vpn_ip_intel.LOOKUP_WARN_BYTES", 1)  # force the warning
        out = tmp_path / "vpn_relay_ips.csv"
        with caplog.at_level(logging.WARNING):
            write_lookup_csv(self._sample_nodes(), str(out))
        assert any("10 MB" in r.message for r in caplog.records)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_vpn_ip_intel.py::TestLogScaleLookup::test_write_lookup_derives_path_and_keeps_all_rows -v`
Expected: FAIL — `ImportError: cannot import name 'write_lookup_csv'`

- [ ] **Step 3: Add `write_lookup_csv` and call it in `run()`**

Add this function immediately after `write_csv` (after line 1792):

```python
def write_lookup_csv(nodes: List[Dict], output: str) -> Optional[str]:
    """Write the lean LogScale lookup next to the master CSV, mirroring the
    legacy vpn_exit_ips derivation. Writes ALL rows (exact-IP + CIDR + inactive).
    Returns the lookup path, or None if `output` is not the master CSV."""
    if "vpn_relay_ips" not in output:
        return None
    lookup_path = output.replace("vpn_relay_ips", "vpn_relay_lookup")
    write_csv(nodes, lookup_path, fields=LOOKUP_FIELDS)
    size = os.path.getsize(lookup_path)
    if size > LOOKUP_WARN_BYTES:
        logger.warning(
            f"{lookup_path} is {size / 1e6:.1f} MB — approaching the 10 MB "
            f"LogScale limit; consider a retention cap on inactive rows."
        )
    return lookup_path
```

This uses `Optional`, which is **not** currently imported. Change line 26 from:

```python
from typing import Dict, List
```

to:

```python
from typing import Dict, List, Optional
```

Then in `run()`, immediately after the master write at line 1852 (`write_csv(all_nodes_with_prefix, output)`), add:

```python
    # Write the lean LogScale lookup (all rows, incl. CIDR + inactive)
    write_lookup_csv(all_nodes_with_prefix, output)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_vpn_ip_intel.py::TestLogScaleLookup -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Run the full VPN test suite (no regressions)**

Run: `python -m pytest tests/test_vpn_ip_intel.py -v`
Expected: PASS (all pre-existing tests + the 8 new ones)

- [ ] **Step 6: Commit**

```bash
git add scripts/vpn_ip_intel.py tests/test_vpn_ip_intel.py
git commit -m "feat: emit data/vpn_relay_lookup.csv for LogScale upload"
```

---

### Task 4: Refresh feasible VPN seeds (operational)

**Files:**
- Modify (data): `data/vpn_seeds/expressvpn_data.json`, `data/vpn_seeds/protonvpn/Servers.current.bin`

- [ ] **Step 1: Copy the ExpressVPN + ProtonVPN local caches**

Run in **PowerShell** from the worktree root:

```powershell
Copy-Item "C:\Program Files\ExpressVPN\data\data.json" "data\vpn_seeds\expressvpn_data.json" -Force
$proton = Get-ChildItem "$env:LOCALAPPDATA\Proton\Proton VPN\Storage\Servers.*.bin" | Select-Object -First 1
Copy-Item $proton.FullName "data\vpn_seeds\protonvpn\Servers.current.bin" -Force
```

- [ ] **Step 2: Verify the copies landed and are non-empty**

Run: `git status --short data/vpn_seeds/` — expect both files modified.
Confirm `Servers.current.bin` is ~1.3 MB (not 0 bytes).

- [ ] **Step 3: Commit the refreshed seeds**

```bash
git add data/vpn_seeds/expressvpn_data.json data/vpn_seeds/protonvpn/Servers.current.bin
git commit -m "data: refresh ExpressVPN + ProtonVPN seeds (2026-07-07)"
```

> **Not done here** (require user action, per design): Mullvad exit probe (needs an active Mullvad WireGuard connection) and the annual Astrill/Spur seed.

---

### Task 5: Run the pipeline locally and commit regenerated data

**Files:**
- Modify (data): `data/vpn_relay_ips.csv`, `data/vpn_relay_lookup.csv` (new), `data/vpn_exit_ips.csv`, `data/vpn_exit_ips/*.csv`

- [ ] **Step 1: Run the collection pipeline**

Requires the repo `.env` (Shodan etc.) for full provider coverage; missing keys degrade individual providers but still produce output. Takes several minutes (external APIs + RDAP).

Run: `python scripts/vpn_ip_intel.py`
Expected (tail): `Wrote N rows to data/vpn_relay_ips.csv`, `Wrote N rows to data/vpn_relay_lookup.csv`, `Total: ...`.

- [ ] **Step 2: Verify the lookup — size under 10 MB and row parity with the master**

Run:

```bash
python -c "import os,csv; \
m=sum(1 for _ in open('data/vpn_relay_ips.csv',encoding='utf-8'))-1; \
l=sum(1 for _ in open('data/vpn_relay_lookup.csv',encoding='utf-8'))-1; \
mb=os.path.getsize('data/vpn_relay_lookup.csv')/1e6; \
print(f'master={m} lookup={l} size={mb:.2f}MB'); \
assert m==l, 'row parity failed'; assert mb < 10, 'over 10MB'; \
print('OK: parity + under 10MB')"
```

Expected: `OK: parity + under 10MB`

- [ ] **Step 3: Verify the lookup header is exactly the 13 columns**

Run: `python -c "import csv; print(next(csv.reader(open('data/vpn_relay_lookup.csv',encoding='utf-8'))))"`
Expected: `['ip', 'prefix', 'provider', 'asn', 'asn_name', 'source_date', 'score_prehire', 'tier_prehire', 'score_posthire', 'tier_posthire', 'first_seen', 'last_seen', 'active']`

- [ ] **Step 4: Commit the regenerated data**

```bash
git add data
git commit -m "data: regenerate VPN relay CSV + LogScale lookup (refreshed seeds)"
```

---

### Task 6: Update the operations guide

**Files:**
- Modify: `docs/vpn-ip-intel-operations.md` (Output Files table, ~line 88-93)

- [ ] **Step 1: Add the lookup to the Output Files table**

Add this row under the existing table:

```markdown
| `data/vpn_relay_lookup.csv` | Lean 13-col LogScale lookup (all rows, <10 MB) | Daily (auto) |
```

- [ ] **Step 2: Commit**

```bash
git add docs/vpn-ip-intel-operations.md
git commit -m "docs: document vpn_relay_lookup.csv in operations guide"
```

---

## Finalize

- [ ] Push the branch and open a PR referencing the issue from Task 0:

```bash
git push -u origin feature/vpn-relay-logscale-lookup
gh pr create --fill
```

- [ ] After merge, remove the worktree: `git worktree remove .worktrees/vpn-relay-lookup`
