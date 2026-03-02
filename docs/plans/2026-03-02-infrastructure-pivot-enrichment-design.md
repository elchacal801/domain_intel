# Infrastructure Pivot Enrichment — Design

## Context

Inspired by the FT/Krebs story where 442 seemingly independent companies were linked through a single private MX server (`mx.phoenixtrading.ltd`), revealing a $90B Russian oil smuggling network. Domain Intel already performs MX clustering, but currently focuses on DEA/typosquat domains. This feature extends the platform to detect and investigate "legitimate-looking shell company networks" — domains that appear normal individually but cluster on suspicious private infrastructure, especially when entity screening (OpenSanctions, ICIJ, GLEIF) reveals connections to sanctioned entities or leaked databases.

## Design

### Phase 1: Infrastructure Search + Entity Highlights

**Goal:** Let analysts start investigations from infrastructure indicators (MX hosts, IPs) instead of only domain names, with entity screening data prominently displayed.

#### 1a. Extend Investigate page search

**File:** `frontend/src/pages/InvestigateLanding.jsx`

The existing `handlePivot` function already queries `infraIndex` for MX hosts, IPs, ASNs, and A-records. Extend this:

- **Input classification:** When user submits a search, check `infraIndex` keys (mx, ip, asn, a_record) for matches BEFORE treating input as a domain name. If a match is found, render infrastructure results instead of navigating to domain detail.
- **Results view:** New `InfraResults` component showing:
  - Infrastructure header: MX host/IP, ASN, country, cluster size
  - Domain table: all domains sharing this infrastructure, with columns:
    - Domain name (linked to detail page)
    - Registrant org (from WHOIS)
    - Entity flags: OpenSanctions score, ICIJ match, GLEIF status (color-coded icons)
    - Risk score / Confidence badge
    - TLD
  - Entity screening summary banner: "X of Y domains have entity screening hits"
  - Shared provider status: whether this MX is known infrastructure or private
  - "Search in OTX" button — opens `https://otx.alienvault.com/indicator/hostname/{mx_host}` in new tab
  - "Search in Silent Push" button — opens `https://explore.silentpush.com/enrichment/domain/{mx_host}` for hostnames, or `https://explore.silentpush.com/enrichment/ipv4/{ip}` for IPv4 addresses
  - "Add to pipeline" hint — instructs analyst to add domains to `manual_candidates.csv`

#### 1b. Enrich infra_index with entity screening data

**File:** `scripts/build_frontend_data.py`

Currently `infra_index.json` stores `{ mx: { hostname: [domains...] }, ... }`. Extend each entry from a plain domain list to an object with pre-computed entity screening aggregates:

```json
{
  "mx": {
    "mail.example.com": {
      "domains": ["domain1.com", "domain2.com"],
      "private": true,
      "entity_stats": {
        "os_hits": 3,
        "icij_hits": 1,
        "gleif_active": 2,
        "unique_registrants": 4,
        "total": 5
      }
    }
  }
}
```

**Shared provider detection:** Reuse existing `shared_infrastructure.yaml` patterns to mark each MX host as `private: true/false`.

#### 1c. Pre-compute OTX expansion for private MX clusters

**File:** New script `scripts/expand_mx_clusters.py`

For each private MX cluster with 5+ domains:
1. Query OTX passive DNS for the MX hostname
2. Extract additional domains resolving to that MX
3. Output `data/mx_expansion.csv` with columns: `mx_host, discovered_domain, source`
4. Merged into pipeline on next run via `merge_lists_v3b.py`

**CI integration:** Optional step in `.github/workflows/update_intelligence.yml`, gated on OTX API availability.

---

### Phase 2: Proactive Cluster Entity Screening

**Goal:** Automatically flag clusters where private infrastructure serves domains with entity screening hits.

#### 2a. Compute cluster entity stats in build pipeline

**File:** `scripts/build_frontend_data.py`

After clusters are computed, add a post-processing step per cluster:
- `os_hit_count`: domains with `os_match_score > 0`
- `icij_hit_count`: domains with `icij_entity_match` populated
- `gleif_active_count`: domains with `gleif_status == "ACTIVE"`
- `unique_registrants`: count of distinct `whois_registrar` values
- `registrant_diversity`: `unique_registrants / cluster_size`
- `entity_risk` flag: TRUE if private infrastructure AND 2+ entity hits

#### 2b. Surface entity-linked clusters in frontend

**Files:** `ClusterView.jsx`, `MatchDashboard.jsx`

- Entity Screening section in cluster detail sidebar
- Filter toggle: "Show entity-linked clusters only"
- Visual badge (shield icon) on entity-linked clusters
- New KPI card: "Entity-Linked Clusters"

---

### Files to Modify

| File | Phase | Changes |
|------|-------|---------|
| `frontend/src/pages/InvestigateLanding.jsx` | 1a | Infrastructure search detection, InfraResults component |
| `scripts/build_frontend_data.py` | 1b, 2a | Enriched infra_index, cluster entity stats |
| `scripts/expand_mx_clusters.py` | 1c | New script: OTX passive DNS expansion |
| `frontend/src/pages/ClusterView.jsx` | 2b | Entity screening sidebar, filter, badges |
| `frontend/src/pages/MatchDashboard.jsx` | 2b | Entity-Linked Clusters KPI |
| `.github/workflows/update_intelligence.yml` | 1c | Add expand_mx_clusters step |
| `scripts/merge_lists_v3b.py` | 1c | Accept mx_expansion.csv as input source |

### Existing utilities to reuse

- `scripts/shared/retry.py` — `@retry` decorator for OTX API calls
- `scripts/shared/api_budget.py` — API rate limiting
- `config/shared_infrastructure.yaml` — private vs shared MX classification
- `infra_index` builder in `build_frontend_data.py` (lines 303-353)
- Cluster confidence scoring (lines 453-597)
- OTX integration patterns from `enrich_reputation.py`
