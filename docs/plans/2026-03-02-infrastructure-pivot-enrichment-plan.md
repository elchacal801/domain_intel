# Infrastructure Pivot Enrichment — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend Domain Intel to detect shell company networks by enabling infrastructure-first investigations (search by MX host/IP) with entity screening highlights, and proactively flag clusters where private infrastructure serves domains with sanctions/leak database hits.

**Architecture:** Two phases — Phase 1 enriches `infra_index.json` with entity stats and builds an `InfraResults` frontend component on the Investigate page. Phase 2 adds cluster-level entity screening stats to `clusters.json` and surfaces them in ClusterView and MatchDashboard. A new `expand_mx_clusters.py` script uses OTX passive DNS to discover additional domains on private MX hosts.

**Tech Stack:** Python 3 (build scripts, OTX API), React 19 + Tailwind CSS 4 (frontend), pytest (tests)

**Design doc:** `docs/plans/2026-03-02-infrastructure-pivot-enrichment-design.md`

---

## Task 1: Enrich infra_index with entity stats and private flag

**Files:**
- Modify: `scripts/build_frontend_data.py` (lines 303-353, `build_infra_index` function)
- Test: `tests/test_build_frontend_data.py` (new or extend)

**Context:** Currently `infra_index.json` stores `{ mx: { hostname: [domain_strings] } }`. We need `{ mx: { hostname: { domains: [...], private: bool, entity_stats: {...} } } }`. The build function receives `domains` dict (keyed by domain name, values are enriched data dicts with fields like `os_match_score`, `icij_entity_match`, `gleif_status`, `registrant_org`) and `fp_matches`.

The function `match_shared_provider(value, "mx", config)` (lines 403-450) already exists and returns provider info or None — reuse it to determine `private` flag.

**Step 1: Write failing test**

Create `tests/test_infra_index_enrichment.py`:

```python
"""Tests for enriched infra_index with entity stats and private flag."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

def test_enriched_mx_index_has_entity_stats():
    """MX index entries should have domains list, private flag, and entity_stats."""
    from build_frontend_data import build_infra_index
    domains = {
        "shell1.com": {
            "primary_mx": "mx.private-host.com",
            "mx_ip": "1.2.3.4",
            "asn": "12345",
            "a_record": "5.6.7.8",
            "registrant_org": "Shell Corp A",
            "os_match_score": "85",
            "icij_entity_match": "",
            "gleif_status": "ACTIVE",
            "gleif_lei": "ABC123",
        },
        "shell2.com": {
            "primary_mx": "mx.private-host.com",
            "mx_ip": "1.2.3.4",
            "asn": "12345",
            "a_record": "5.6.7.8",
            "registrant_org": "Shell Corp B",
            "os_match_score": "70",
            "icij_entity_match": "Panama Papers",
            "gleif_status": "",
            "gleif_lei": "",
        },
        "shell3.com": {
            "primary_mx": "mx.private-host.com",
            "mx_ip": "1.2.3.4",
            "asn": "12345",
            "a_record": "5.6.7.8",
            "registrant_org": "Shell Corp A",
            "os_match_score": "",
            "icij_entity_match": "",
            "gleif_status": "",
            "gleif_lei": "",
        },
    }
    fp_matches = {}
    index = build_infra_index(domains, fp_matches)

    mx_entry = index["mx"]["mx.private-host.com"]
    assert isinstance(mx_entry, dict), "MX entry should be a dict, not a list"
    assert set(mx_entry["domains"]) == {"shell1.com", "shell2.com", "shell3.com"}
    assert mx_entry["private"] is True  # not a known shared provider

    stats = mx_entry["entity_stats"]
    assert stats["os_hits"] == 2      # shell1 (85) + shell2 (70)
    assert stats["icij_hits"] == 1    # shell2 only
    assert stats["gleif_active"] == 1 # shell1 only
    assert stats["unique_registrants"] == 2  # "Shell Corp A" + "Shell Corp B"
    assert stats["total"] == 3


def test_shared_provider_marked_not_private():
    """Known shared providers (Google, Microsoft) should have private=False."""
    from build_frontend_data import build_infra_index
    domains = {
        "user1.com": {
            "primary_mx": "aspmx.l.google.com",
            "mx_ip": "142.251.40.26",
            "asn": "15169",
            "a_record": "",
            "registrant_org": "User 1",
            "os_match_score": "",
            "icij_entity_match": "",
            "gleif_status": "",
            "gleif_lei": "",
        },
        "user2.com": {
            "primary_mx": "aspmx.l.google.com",
            "mx_ip": "142.251.40.26",
            "asn": "15169",
            "a_record": "",
            "registrant_org": "User 2",
            "os_match_score": "",
            "icij_entity_match": "",
            "gleif_status": "",
            "gleif_lei": "",
        },
    }
    fp_matches = {}
    index = build_infra_index(domains, fp_matches)

    mx_entry = index["mx"]["aspmx.l.google.com"]
    assert mx_entry["private"] is False


def test_non_mx_categories_also_enriched():
    """ASN, IP, registrar, a_record, fp categories should also use enriched format."""
    from build_frontend_data import build_infra_index
    domains = {
        "d1.com": {
            "primary_mx": "", "mx_ip": "", "asn": "16509",
            "a_record": "1.2.3.4", "registrant_org": "Org A",
            "os_match_score": "50", "icij_entity_match": "", "gleif_status": "", "gleif_lei": "",
        },
        "d2.com": {
            "primary_mx": "", "mx_ip": "", "asn": "16509",
            "a_record": "1.2.3.4", "registrant_org": "Org B",
            "os_match_score": "", "icij_entity_match": "Offshore", "gleif_status": "", "gleif_lei": "",
        },
    }
    fp_matches = {}
    index = build_infra_index(domains, fp_matches)

    asn_entry = index["asn"]["16509"]
    assert isinstance(asn_entry, dict)
    assert set(asn_entry["domains"]) == {"d1.com", "d2.com"}
    assert asn_entry["entity_stats"]["os_hits"] == 1
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_infra_index_enrichment.py -v
```
Expected: FAIL — `build_infra_index` returns lists not dicts.

**Step 3: Implement enriched build_infra_index**

In `scripts/build_frontend_data.py`, replace the `build_infra_index` function (lines 303-353). The new version:

1. Builds raw buckets the same way (domain lists per key)
2. For each bucket, computes entity stats by looking up domain data
3. For MX buckets, checks `match_shared_provider()` to set `private` flag
4. Returns enriched structure

Key implementation notes:
- The `domains` dict is passed in — each value has fields like `os_match_score`, `icij_entity_match`, `gleif_status`, `registrant_org`
- `match_shared_provider(mx_host, "mx", shared_config)` needs the shared infra config — pass it as a parameter or load it inside the function
- The shared infra config is loaded at module level (line ~400) — `load_shared_infra_config()`
- For non-MX categories, `private` is less meaningful but still useful for IP/ASN (check if ASN is in known providers)
- Entity stats computation: iterate domain list, check each domain's entity fields

**Step 4: Run test to verify it passes**

```bash
pytest tests/test_infra_index_enrichment.py -v
```

**Step 5: Update existing infra_index consumers**

The frontend `InvestigateLanding.jsx` handleSubmit function (lines 34-58) currently does `infraIndex.mx[key]` expecting an array. After this change, it returns `{domains: [...], ...}`. Update all pivot lookups to access `.domains` property.

The `GlobalSearch.jsx` does NOT use infraIndex (it uses Fuse.js on fpMatches), so no change needed there.

**Step 6: Commit**

```bash
git add scripts/build_frontend_data.py tests/test_infra_index_enrichment.py
git commit -m "feat: enrich infra_index with entity stats and private flag"
```

---

## Task 2: Update InvestigateLanding.jsx for enriched infra_index

**Files:**
- Modify: `frontend/src/pages/InvestigateLanding.jsx` (lines 28-69, handleSubmit + pivot rendering)

**Context:** The handleSubmit function currently parses `ASN:value`, `MX:value`, `REG:value`, `FP:value` prefixes and queries `infraIndex[type][key]` which returned `string[]`. Now it returns `{domains: string[], private: bool, entity_stats: {...}}`.

Also need to add direct infrastructure search: if a user types an MX hostname or IP without a prefix, detect it and auto-pivot.

**Step 1: Update pivot result extraction**

In `handleSubmit()`, change all `infraIndex.xxx[key]` accesses to extract `.domains`:

```javascript
// ASN pivot (line 43)
const entry = infraIndex.asn?.[val];
if (entry) results.push(...(entry.domains || []));

// MX pivot (lines 44-49) — partial match
for (const [key, entry] of Object.entries(infraIndex.mx || {})) {
  if (key.toLowerCase().includes(val.toLowerCase())) {
    results.push(...(entry.domains || []));
    // Store matched infra metadata for InfraResults
    matchedInfra = { type: 'mx', key, ...entry };
  }
}
```

**Step 2: Add auto-detection for infrastructure inputs (no prefix)**

Before treating input as a domain name (the `else` branch at line 60), check:
- Does input match an IP pattern (`/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/`)? → search `infraIndex.ip` and `infraIndex.a_record`
- Does input exist as a key in `infraIndex.mx`? → MX pivot
- Otherwise → domain search (existing behavior)

**Step 3: Store matched infrastructure metadata in state**

Add new state: `const [infraMeta, setInfraMeta] = useState(null);`

When an infrastructure pivot succeeds, store the matched entry's metadata (private flag, entity_stats) so the InfraResults component can display it.

**Step 4: Commit**

```bash
git add frontend/src/pages/InvestigateLanding.jsx
git commit -m "feat: update pivot search for enriched infra_index format"
```

---

## Task 3: Create InfraResults component

**Files:**
- Create: `frontend/src/components/InfraResults.jsx`
- Modify: `frontend/src/pages/InvestigateLanding.jsx` (render InfraResults when infra pivot)

**Context:** When an infrastructure pivot returns results, render a dedicated results view instead of the simple domain list. The component receives: `infraMeta` (type, key, private, entity_stats), `domains` (array of domain strings), and `loadDomain` function from DataContext to fetch full domain records.

**Step 1: Create InfraResults component**

```jsx
// frontend/src/components/InfraResults.jsx
import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useData } from '@/context/DataContext';
import ConfidenceBadge from '@/components/ConfidenceBadge';
import {
  Server, Globe, Shield, ShieldAlert, FileKey, ExternalLink,
  AlertTriangle, Search as SearchIcon
} from 'lucide-react';
```

Component structure:
1. **Header bar** — icon + infrastructure identifier (MX host / IP), private/shared badge, cluster size
2. **Entity screening summary banner** — "X of Y domains have entity screening hits" with breakdown (OS/ICIJ/GLEIF counts)
3. **External investigation buttons** — "Search in OTX" + "Search in Silent Push" (open in new tab)
4. **Domain table** — sortable, paginated (PAGE_SIZE=50), with columns:
   - Domain (monospace, linked to `/investigate/{domain}`)
   - Registrant Org
   - OS Score (color-coded: red if >0)
   - ICIJ Match (yellow if present)
   - GLEIF Status (green if ACTIVE)
   - Risk Score
5. **Add to pipeline hint** — small muted text at bottom

**External link URLs:**
- OTX hostname: `https://otx.alienvault.com/indicator/hostname/{value}`
- OTX IPv4: `https://otx.alienvault.com/indicator/ip/{value}`
- Silent Push hostname: `https://explore.silentpush.com/enrichment/domain/{value}`
- Silent Push IPv4: `https://explore.silentpush.com/enrichment/ipv4/{value}`

**Data loading:** The component receives domain name strings but needs full domain records for entity screening columns. Use `loadDomain()` from DataContext to fetch each domain's data asynchronously. Cache results in component state.

**Styling:** Follow Crimson Vector design system — `glass-card` containers, `var(--bg-surface)` backgrounds, no shadows, muted text colors, crimson accents on entity hit counts.

**Step 2: Integrate into InvestigateLanding.jsx**

When `pivotResults` is populated AND `infraMeta` is set, render `<InfraResults>` instead of the current simple domain list (lines 178-220).

**Step 3: Commit**

```bash
git add frontend/src/components/InfraResults.jsx frontend/src/pages/InvestigateLanding.jsx
git commit -m "feat: add InfraResults component for infrastructure pivot investigations"
```

---

## Task 4: Compute cluster entity stats in build pipeline

**Files:**
- Modify: `scripts/build_frontend_data.py` (after cluster computation, ~line 825)
- Test: `tests/test_cluster_entity_stats.py`

**Context:** After `compute_clusters()` returns `{nodes, edges}`, post-process each infrastructure node to add entity screening aggregates. The `domains` dict has all entity screening fields. Need to find which domains belong to each cluster by traversing edges.

**Step 1: Write failing test**

```python
def test_cluster_entity_stats_computed():
    """Infrastructure nodes should have entity screening stats."""
    clusters = {
        "nodes": [
            {"id": "mx:mail.bad.com", "type": "mx_host", "shared_infra": False},
            {"id": "dom:shell1.com", "type": "domain"},
            {"id": "dom:shell2.com", "type": "domain"},
        ],
        "edges": [
            {"source": "dom:shell1.com", "target": "mx:mail.bad.com"},
            {"source": "dom:shell2.com", "target": "mx:mail.bad.com"},
        ],
    }
    domains = {
        "shell1.com": {"os_match_score": "85", "icij_entity_match": "", "gleif_status": "ACTIVE", "whois_registrar": "Reg A"},
        "shell2.com": {"os_match_score": "", "icij_entity_match": "Panama Papers", "gleif_status": "", "whois_registrar": "Reg B"},
    }
    from build_frontend_data import enrich_clusters_with_entity_stats
    enrich_clusters_with_entity_stats(clusters, domains)

    infra_node = clusters["nodes"][0]
    assert infra_node["entity_stats"]["os_hits"] == 1
    assert infra_node["entity_stats"]["icij_hits"] == 1
    assert infra_node["entity_stats"]["gleif_active"] == 1
    assert infra_node["entity_stats"]["unique_registrants"] == 2
    assert infra_node["entity_risk"] is True  # private infra + >=2 entity hits
```

**Step 2: Run test to verify it fails**

**Step 3: Implement `enrich_clusters_with_entity_stats(clusters, domains)`**

New function in `build_frontend_data.py`:

1. Build edge map: for each infrastructure node, collect connected domain IDs
2. Strip `dom:` prefix to get domain name, look up in `domains` dict
3. Count entity screening hits across member domains
4. Set `entity_risk = True` if `not shared_infra AND (os_hits + icij_hits + gleif_active) >= 2`
5. Add `entity_stats` dict and `entity_risk` bool to each infra node

Call it right after `compute_clusters()` in the main flow (~line 961).

**Step 4: Run test, verify pass**

**Step 5: Commit**

```bash
git add scripts/build_frontend_data.py tests/test_cluster_entity_stats.py
git commit -m "feat: compute entity screening stats per cluster"
```

---

## Task 5: Update stats.json with entity_linked_clusters count

**Files:**
- Modify: `scripts/build_frontend_data.py` (`compute_stats` function, ~line 838)

**Step 1: Add entity_linked_clusters to stats computation**

In `compute_stats()`, count infrastructure nodes where `entity_risk is True`:

```python
entity_linked = sum(1 for n in clusters["nodes"]
                    if n.get("type") != "domain" and n.get("entity_risk"))
stats["entity_linked_clusters"] = entity_linked
```

**Step 2: Verify by running build and checking stats.json**

```bash
python scripts/build_frontend_data.py
python -c "import json; d=json.load(open('docs/data/stats.json')); print('entity_linked_clusters:', d.get('entity_linked_clusters'))"
```

**Step 3: Commit**

```bash
git add scripts/build_frontend_data.py
git commit -m "feat: add entity_linked_clusters count to stats.json"
```

---

## Task 6: Update ClusterView sidebar with entity screening

**Files:**
- Modify: `frontend/src/pages/ClusterView.jsx` (sidebar section, ~lines 377-472)

**Context:** The cluster sidebar already shows confidence breakdown, shared infra banner, related MX hosts, and hosting ASN. Add an "Entity Screening" section below the confidence breakdown. Also add a filter toggle and sort option.

**Step 1: Add Entity Screening section to sidebar**

After the confidence breakdown section (~line 408), add:

```jsx
{/* Entity Screening */}
{selectedCluster.entity_stats && (
  <div className="space-y-2">
    <div className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">
      Entity Screening
    </div>
    <div className="grid grid-cols-3 gap-2">
      <EntityStatCard label="OpenSanctions" count={selectedCluster.entity_stats.os_hits} color="#ef4444" />
      <EntityStatCard label="ICIJ" count={selectedCluster.entity_stats.icij_hits} color="#eab308" />
      <EntityStatCard label="GLEIF Active" count={selectedCluster.entity_stats.gleif_active} color="#22c55e" />
    </div>
    <div className="text-[10px] text-text-muted">
      {selectedCluster.entity_stats.unique_registrants} unique registrant(s) across {selectedCluster.domain_count} domains
    </div>
    {selectedCluster.entity_risk && (
      <div className="flex items-center gap-1.5 rounded border border-[#C0272D]/20 bg-[#C0272D]/5 px-2.5 py-1.5 text-[10px] text-[#C0272D]">
        <ShieldAlert className="h-3 w-3" />
        Entity-linked cluster — private infrastructure with entity screening hits
      </div>
    )}
  </div>
)}
```

Helper component:
```jsx
function EntityStatCard({ label, count, color }) {
  return (
    <div className="rounded border border-border-subtle p-2 text-center" style={{ background: 'var(--bg-surface)' }}>
      <div className="font-mono text-sm font-bold" style={{ color: count > 0 ? color : 'var(--text-muted)' }}>
        {count}
      </div>
      <div className="text-[9px] text-text-muted">{label}</div>
    </div>
  );
}
```

**Step 2: Add entity risk filter toggle**

Add state: `const [entityOnly, setEntityOnly] = useState(false);`

In the filter/controls area, add toggle button. Filter cluster table: if `entityOnly`, only show clusters where `entity_risk === true`.

**Step 3: Add entity risk badge to cluster list**

In the cluster table rows (the `buildClusterTable` function output rendering), add a small `ShieldAlert` icon next to clusters with `entity_risk: true`.

**Step 4: Commit**

```bash
git add frontend/src/pages/ClusterView.jsx
git commit -m "feat: add entity screening section to cluster sidebar"
```

---

## Task 7: Add Entity-Linked Clusters KPI to MatchDashboard

**Files:**
- Modify: `frontend/src/pages/MatchDashboard.jsx` (KPI grid, ~line 185)

**Step 1: Add new KPI card**

Add `ShieldAlert` to lucide imports. Add KPI card to the grid:

```jsx
<KpiCard
  icon={ShieldAlert}
  label="Entity-Linked"
  value={stats?.entity_linked_clusters?.toLocaleString()}
  color="#C0272D"
  tooltip="Infrastructure clusters on private MX/IP with entity screening hits (OpenSanctions, ICIJ, GLEIF)"
/>
```

Change grid from `sm:grid-cols-4` to `sm:grid-cols-5` to accommodate 5 KPIs.

Also add tooltip to `kpiTooltips` in `frontend/src/data/fpRegistry.js`:
```javascript
entity_linked_clusters: 'Private infrastructure clusters where domains have sanctions, leak database, or legal entity screening hits',
```

**Step 2: Commit**

```bash
git add frontend/src/pages/MatchDashboard.jsx frontend/src/data/fpRegistry.js
git commit -m "feat: add Entity-Linked Clusters KPI card"
```

---

## Task 8: Create expand_mx_clusters.py script

**Files:**
- Create: `scripts/expand_mx_clusters.py`
- Test: `tests/test_expand_mx_clusters.py`

**Context:** For each private MX cluster with ≥5 domains (read from `infra_index.json`), query OTX passive DNS to discover additional domains. Output `data/mx_expansion.csv`. Follow existing patterns: argparse, load_dotenv, @retry decorator, api_budget.

**Step 1: Write failing test**

```python
def test_extract_mx_targets_from_infra_index():
    """Should extract private MX hosts with 5+ domains from enriched infra_index."""
    from expand_mx_clusters import extract_mx_targets
    infra_index = {
        "mx": {
            "mx.private.com": {
                "domains": ["d1.com", "d2.com", "d3.com", "d4.com", "d5.com"],
                "private": True,
                "entity_stats": {"os_hits": 1, "icij_hits": 0, "gleif_active": 0, "unique_registrants": 5, "total": 5}
            },
            "aspmx.l.google.com": {
                "domains": ["g1.com", "g2.com", "g3.com", "g4.com", "g5.com", "g6.com"],
                "private": False,
                "entity_stats": {"os_hits": 0, "icij_hits": 0, "gleif_active": 0, "unique_registrants": 6, "total": 6}
            },
            "mx.small.com": {
                "domains": ["s1.com", "s2.com"],
                "private": True,
                "entity_stats": {"os_hits": 0, "icij_hits": 0, "gleif_active": 0, "unique_registrants": 2, "total": 2}
            },
        }
    }
    targets = extract_mx_targets(infra_index, min_size=5)
    assert targets == ["mx.private.com"]  # only private with 5+ domains
```

**Step 2: Run test to verify it fails**

**Step 3: Implement script**

```python
#!/usr/bin/env python3
"""Expand private MX clusters via OTX passive DNS.

For each private MX host serving 5+ domains, queries OTX to discover
additional domains using that MX. Outputs data/mx_expansion.csv.
"""
import argparse, csv, json, os, sys, logging
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from shared.retry import retry

load_dotenv()
log = logging.getLogger(__name__)

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_HOSTNAME_URL = "https://otx.alienvault.com/api/v1/indicators/hostname/{}/passive_dns"


def extract_mx_targets(infra_index, min_size=5):
    """Return list of private MX hostnames with >= min_size domains."""
    targets = []
    for mx_host, entry in infra_index.get("mx", {}).items():
        if isinstance(entry, dict) and entry.get("private") and len(entry.get("domains", [])) >= min_size:
            targets.append(mx_host)
    return sorted(targets)


@retry(max_retries=3, base_delay=2.0)
def query_otx_pdns(hostname):
    """Query OTX passive DNS for a hostname, return list of discovered domains."""
    import requests
    if not OTX_API_KEY:
        return []
    url = OTX_HOSTNAME_URL.format(hostname)
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code == 200:
        data = resp.json()
        records = data.get("passive_dns", [])
        return list({r.get("hostname") for r in records if r.get("hostname")})
    if resp.status_code == 429:
        log.warning("OTX rate limited for %s", hostname)
    return []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--infra-index", default="docs/data/infra_index.json")
    parser.add_argument("--output", default="data/mx_expansion.csv")
    parser.add_argument("--min-size", type=int, default=5)
    args = parser.parse_args()

    with open(args.infra_index) as f:
        infra_index = json.load(f)

    targets = extract_mx_targets(infra_index, args.min_size)
    log.info("Found %d private MX targets with %d+ domains", len(targets), args.min_size)

    rows = []
    for mx_host in targets:
        known = set(infra_index["mx"][mx_host]["domains"])
        discovered = query_otx_pdns(mx_host)
        new_domains = [d for d in discovered if d not in known]
        for domain in new_domains:
            rows.append({"mx_host": mx_host, "discovered_domain": domain, "source": "otx_pdns"})
        log.info("  %s: %d known, %d discovered, %d new", mx_host, len(known), len(discovered), len(new_domains))

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["mx_host", "discovered_domain", "source"])
        writer.writeheader()
        writer.writerows(rows)
    log.info("Wrote %d expanded domains to %s", len(rows), args.output)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    main()
```

**Step 4: Run test, verify pass**

**Step 5: Commit**

```bash
git add scripts/expand_mx_clusters.py tests/test_expand_mx_clusters.py
git commit -m "feat: add expand_mx_clusters.py for OTX passive DNS expansion"
```

---

## Task 9: Build, verify end-to-end, final commit

**Step 1: Run full build pipeline**

```bash
python scripts/build_frontend_data.py
```

Verify:
```bash
python -c "
import json
idx = json.load(open('docs/data/infra_index.json'))
# Check enriched format
sample_mx = next(iter(idx['mx'].values()))
print('MX entry type:', type(sample_mx))
print('Has domains:', 'domains' in sample_mx)
print('Has private:', 'private' in sample_mx)
print('Has entity_stats:', 'entity_stats' in sample_mx)

# Check cluster entity stats
clusters = json.load(open('docs/data/clusters.json'))
entity_nodes = [n for n in clusters['nodes'] if n.get('entity_risk')]
print(f'Entity-linked clusters: {len(entity_nodes)}')

stats = json.load(open('docs/data/stats.json'))
print(f'Stats entity_linked_clusters: {stats.get(\"entity_linked_clusters\")}')
"
```

**Step 2: Build frontend**

```bash
cd frontend && npm run build
```

Expected: Clean build, no errors.

**Step 3: Visual verification**

Start dev server, verify:
- Navigate to Investigate page
- Search for an MX host (e.g., `MX:temp-mail-pro.com`) → see InfraResults with entity columns
- Search for an IP → auto-detected as infrastructure, shows results
- OTX + Silent Push buttons open correct URLs in new tabs
- Navigate to Clusters page → entity screening section in sidebar
- Entity-linked filter toggle works
- MatchDashboard shows Entity-Linked KPI card

**Step 4: Final commit with all build outputs**

```bash
git add docs/data/ frontend/src/ scripts/ tests/
git commit -m "feat: infrastructure pivot enrichment — entity screening + cluster analysis"
```
