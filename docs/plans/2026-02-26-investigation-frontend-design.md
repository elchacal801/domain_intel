# Investigation Frontend & Data Transformer — Design

**Date:** 2026-02-26
**Status:** Approved
**Replaces:** Current Vite + vanilla JS summary dashboard

## 1. Overview

Replace the existing 5-tab Chart.js dashboard with a focused 3-screen React investigation frontend. All screens are fully static (GitHub Pages), consuming JSON files generated during the CI build. No API server.

### Screens
| Route | Purpose |
|---|---|
| `/matches` (default) | Sortable/filterable table of all fingerprint-matched domains |
| `/investigate/:domain` | Single-domain deep-dive with all enrichment data |
| `/clusters` | Interactive network graph of infrastructure clusters |

## 2. Data Transformer — `scripts/build_frontend_data.py`

### Input Files
| File | Required | Notes |
|---|---|---|
| `data/dea_domains_probed.csv` | Yes | 49-column enriched domain list (~44MB) |
| `data/fingerprint_matches.csv` | Yes | `domain,fp_id,fp_name,confidence,flame_tp_ids,evidence` |
| `data/ai_classifications.csv` | No | AI threat classifications |
| `data/ai_typosquats.csv` | No | AI typosquat analysis |
| `data/openclaw_exposed.csv` | No | Shadow AI exposure |
| `data/openclaw_stix.json` | No | STIX relationships |
| `data/shodan_intelligence.csv` | No | Port/vuln intel |
| `data/phishtank_matches.csv` | No | PhishTank/URLhaus hits |

### Processing Steps
1. **Load** `dea_domains_probed.csv` into a dict keyed by domain (single pass).
2. **Left-join** `fingerprint_matches.csv` — group matches by domain, attach as list.
3. **Left-join** optional CSVs (ai_classifications, shodan, phishtank, etc.) by domain.
4. **Compute clusters** — group domains by three infrastructure link types:
   - **Shared MX host**: domains sharing the same `primary_mx` value
   - **Shared IP**: domains sharing the same `mx_ip` value
   - **Shared registrar+NS**: domains sharing identical `registrant_org` + `nameservers` combination
   - Only emit clusters with **3+ domains**
5. **Compute stats** — total domains, matched count, cluster count, TLD distribution, top fingerprints.
6. **Write outputs** to `docs/data/`:

### Output Files
| File | Shape | Size Estimate |
|---|---|---|
| `domains.json` | `{ "domain.com": { ...all fields, matches: [...] } }` | ~15MB |
| `fingerprint_matches.json` | `[ { domain, fp_id, fp_name, confidence, flame_tp_ids, evidence, tld, registrar } ]` | ~500KB |
| `clusters.json` | `{ nodes: [...], edges: [...] }` | ~200KB |
| `stats.json` | `{ total, matched, clusters, tld_dist, top_fps, last_updated }` | ~5KB |

### Error Handling
- Missing **required** files → exit with error code 1.
- Missing **optional** files → log warning, omit that data section, continue.
- Empty CSVs (header only) → treat as zero records.

### Cluster Node/Edge Schema
```json
// nodes
{ "id": "mx:mail.provider.com", "type": "mx_host", "label": "mail.provider.com", "size": 15 }
{ "id": "ip:1.2.3.4", "type": "ip", "label": "1.2.3.4", "size": 8 }
{ "id": "regns:NameCheap|ns1.example.com,ns2.example.com", "type": "registrar_ns", "label": "NameCheap + ns1/ns2.example.com", "size": 12 }
{ "id": "dom:evil.com", "type": "domain", "label": "evil.com", "size": 3 }

// edges
{ "source": "dom:evil.com", "target": "mx:mail.provider.com" }
```

Infrastructure nodes sized proportional to connected domain count. Domain nodes are uniformly small.

## 3. React Application Architecture

### Tech Stack
| Layer | Choice | Rationale |
|---|---|---|
| Framework | React 19 + Vite | Modern, fast builds, existing Vite pattern |
| Styling | Tailwind CSS 4 + shadcn/ui | Utility-first, accessible components |
| Routing | react-router-dom v7 (HashRouter) | Hash routing works on GitHub Pages without server config |
| Search | Fuse.js | Client-side fuzzy search, no server needed |
| Tables | @tanstack/react-table v8 | Headless, sortable, filterable, virtual scrolling |
| Graph | Sigma.js + graphology | WebGL graph rendering, handles hundreds of nodes |
| State | React Context + fetch-on-mount | Simple — data loaded once, no complex state management |

### Source Location
- Source: `frontend/` (replaces existing vanilla JS files)
- Build output: `docs/` (Vite `outDir`)
- Data files: `docs/data/` (untouched by build, consumed at runtime)

### Component Tree
```
App
├── DataProvider (React context — loads all 4 JSON files on mount)
│   └── Layout
│       ├── TopNav
│       │   ├── NavLink: Matches (/matches)
│       │   ├── NavLink: Investigate (/investigate)
│       │   ├── NavLink: Clusters (/clusters)
│       │   └── GlobalSearch (Fuse.js → navigate to /investigate/:domain)
│       └── <Outlet />
│           ├── /matches → MatchDashboard
│           │   ├── StatsBar (from stats.json — total, matched, clusters)
│           │   ├── FilterBar
│           │   │   ├── FingerprintDropdown (multi-select FP IDs)
│           │   │   ├── TLDDropdown
│           │   │   └── RegistrarDropdown
│           │   └── MatchTable (@tanstack/react-table)
│           │       └── Row click → navigate(/investigate/:domain)
│           │
│           ├── /investigate → InvestigateLanding
│           │   └── "Search for a domain above" prompt
│           │
│           ├── /investigate/:domain → DomainDetail
│           │   ├── DomainHeader
│           │   │   ├── Domain name + TLD badge
│           │   │   ├── FLAME TP badges (linked)
│           │   │   └── Confidence score badge (color-coded)
│           │   ├── FingerprintSection
│           │   │   └── Collapsible per-match cards with evidence JSON
│           │   ├── EntityScreeningSection
│           │   │   ├── OpenSanctionsCard (score, entity type, dataset)
│           │   │   ├── ICIJCard (score, entity, dataset, jurisdiction)
│           │   │   └── GLEIFCard (LEI, status, legal name, jurisdiction)
│           │   ├── DNSInfraSection
│           │   │   ├── MX records, NS records, IP, ASN
│           │   │   └── Link to cluster view (if domain is in a cluster)
│           │   ├── AIClassificationSection
│           │   │   ├── Classification label + confidence
│           │   │   └── Typosquat analysis (if present)
│           │   ├── WhoisSection
│           │   │   ├── Registrar, registrant org, creation date, age
│           │   │   └── SSL presence indicator
│           │   └── STIXSection
│           │       └── STIX relationship display (if openclaw_stix.json has entries)
│           │
│           └── /clusters → ClusterView
│               ├── ClusterControls
│               │   ├── TypeFilter (MX / IP / Registrar+NS checkboxes)
│               │   └── MinSizeSlider (3–N domains)
│               ├── SigmaGraph
│               │   ├── Infrastructure nodes: large, colored by type
│               │   │   ├── MX nodes: blue
│               │   │   ├── IP nodes: orange
│               │   │   └── Registrar+NS nodes: green
│               │   ├── Domain nodes: small, gray
│               │   └── Click infra node → highlight connected domains
│               └── ClusterDetailPanel (sidebar)
│                   └── List of connected domains (clickable → /investigate/:domain)
```

### Data Loading Strategy
```
DataProvider mounts:
  → fetch('./data/stats.json')        // tiny, load first
  → fetch('./data/fingerprint_matches.json')  // small, for match table
  → fetch('./data/clusters.json')     // medium, for graph
  → fetch('./data/domains.json')      // large, lazy-load on investigate
```

`domains.json` is ~15MB. Strategy: load it lazily only when the user navigates to `/investigate/:domain` or uses the search bar. Cache in context after first load. The match table and cluster view don't need the full domain data.

### Routing
```javascript
<HashRouter>
  <Routes>
    <Route element={<Layout />}>
      <Route index element={<Navigate to="/matches" />} />
      <Route path="matches" element={<MatchDashboard />} />
      <Route path="investigate" element={<InvestigateLanding />} />
      <Route path="investigate/:domain" element={<DomainDetail />} />
      <Route path="clusters" element={<ClusterView />} />
    </Route>
  </Routes>
</HashRouter>
```

## 4. Screen Designs

### Screen 1: Match Dashboard (`/matches`)

**Layout:** Stats bar on top, filter bar below, full-width table.

**Stats bar:** 4 cards — Total Domains Scanned, Fingerprint Matches, Unique Fingerprints, Infrastructure Clusters.

**Table columns:**
| Column | Sortable | Notes |
|---|---|---|
| Domain | Yes | Clickable → `/investigate/:domain` |
| Fingerprint IDs | Yes | Comma-separated FP-XXXX badges |
| Confidence | Yes | Color-coded: green <50, yellow 50-75, red >75 |
| FLAME TPs | Yes | TP-XXXX badges |
| TLD | Yes | Extracted from domain |
| Registrar | Yes | From joined data |
| Match Date | Yes | From pipeline run date |

**Filters:** Multi-select dropdowns for Fingerprint ID, TLD, Registrar. Text search for domain substring. All filters are AND-combined.

**Data source:** `fingerprint_matches.json` (pre-joined with TLD/registrar in build step).

### Screen 2: Domain Investigation (`/investigate/:domain`)

**Layout:** Full-width single-column, sections stacked vertically with cards.

**Sections** (each a shadcn Card):
1. **Header** — Domain name (large), TLD badge, FLAME TP badges (colored), overall confidence score, link to cluster if clustered.
2. **Fingerprint Matches** — One collapsible card per matched fingerprint. Shows FP ID, name, confidence, and expandable evidence JSON (syntax-highlighted).
3. **Entity Screening** — Three side-by-side cards:
   - OpenSanctions: match score meter, entity type, dataset, entity ID
   - ICIJ: match score meter, entity match, dataset, jurisdiction
   - GLEIF: LEI code, status badge (ACTIVE/INACTIVE), legal name, jurisdiction, has parent
4. **DNS Infrastructure** — MX records, nameservers, IP address, ASN name + number, BGP prefix, country code.
5. **AI Classification** — Classification label, typosquat info (fuzzer, target brand, redirect detection).
6. **WHOIS/RDAP** — Registrar, registrant org, creation date, domain age, SSL present.
7. **STIX Relationships** — If STIX data exists for this domain, show relationship type and connected entities.

**Data source:** `domains.json[domain]` (lazy-loaded).

### Screen 3: Cluster Visualization (`/clusters`)

**Layout:** Full-height graph with controls overlay (top-left) and detail panel (right sidebar, hidden until selection).

**Graph rendering (Sigma.js + graphology):**
- Force-directed layout (ForceAtlas2 via graphology-layout-forceatlas2)
- Infrastructure nodes: large (size proportional to connected domains), colored by type
  - MX host → blue (#3b82f6)
  - IP → orange (#f97316)
  - Registrar+NS → green (#22c55e)
- Domain nodes: small (size 3), gray (#94a3b8)
- Edges: thin, light gray

**Interactions:**
- Zoom/pan (built into Sigma.js)
- Hover node → tooltip with label
- Click infrastructure node → highlight connected domain nodes, show list in sidebar
- Click domain node → navigate to `/investigate/:domain`
- Filter controls: checkboxes for node types, slider for minimum cluster size

**Data source:** `clusters.json` (pre-computed nodes + edges).

## 5. CI Integration

Update `update_intelligence.yml` FINALIZE job:

```yaml
# After fingerprint matching and all enrichments...

- name: Build Frontend Data
  run: python scripts/build_frontend_data.py

- name: Build Frontend
  run: |
    cd frontend
    npm ci
    npm run build
```

The Vite build outputs to `docs/` (configured in `vite.config.js`). `build_frontend_data.py` writes to `docs/data/`. The existing commit step already handles `git add data docs`.

### Build Order in FINALIZE
1. All enrichment scripts (existing)
2. `match_fingerprints.py` (existing)
3. `build_frontend_data.py` (new — replaces build_dashboard_data.py + build_investigate_index.py)
4. `npm ci && npm run build` in `frontend/` (updated for React)
5. Commit and push (existing)

## 6. Migration Notes

### Files Removed
- `docs/index.html` (replaced by React build)
- `docs/app.js` (replaced by React build)
- `docs/assets/` (replaced by React build)
- `frontend/src/main.js`, `data.js`, `charts.js`, `investigate.js` (vanilla JS sources)
- `scripts/build_dashboard_data.py` (replaced by build_frontend_data.py)
- `scripts/build_investigate_index.py` (replaced by build_frontend_data.py)

### Files Preserved
- `docs/data/` — all existing CSV/JSON data files stay
- `docs/data/briefings/` — daily briefing JSONs stay
- `docs/data/screenshots/` — domain screenshots stay
- `docs/plans/` — design docs stay
- `docs/detection_logic.md` — stays

### New Dependencies (frontend/package.json)
- react, react-dom
- react-router-dom
- @tanstack/react-table
- fuse.js
- sigma, graphology, graphology-layout-forceatlas2
- tailwindcss, @tailwindcss/vite
- shadcn/ui components (button, card, badge, table, dropdown-menu, collapsible, slider, input)
