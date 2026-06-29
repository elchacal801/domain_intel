# domain_intel — Full Code Review

**Date:** February 28, 2026
**Scope:** Full repository review — backend pipeline, frontend, CI/CD, data connectivity, security
**Commit depth:** 156 commits, ~50 Python scripts, React frontend, 2 GHA workflows

---

## Executive Summary

domain_intel is a genuinely impressive solo-built threat intelligence platform. The pipeline architecture is production-grade: sharded parallel enrichment via GitHub Actions, YAML-driven fingerprint matching, multi-model LLM fallback chains, budget-guarded API integrations, STIX 2.1 export, and a React investigation frontend with graph visualization. The shared module layer (`retry`, `sanitize`, `api_budget`, `config`, `llm_client`, `flame_client`) shows mature engineering instincts.

The central weakness is **data fragmentation**. You have ~15 enrichment sources producing data that partially merges into the main probed CSV, partially lives in separate files, and partially never reaches the frontend. The intelligence is being collected but not *connected*. Fixing this is the single highest-leverage improvement — it would make every existing feature more powerful without building anything new.

The frontend is clean and well-structured but currently functions as a **viewer** rather than an **analyst workbench**. The data it receives is a subset of what the pipeline produces. Bridging that gap transforms domain_intel from "a dashboard with good data behind it" into "an investigation tool."

---

## 1. Architecture Assessment

### What's Working Well

**Shared module layer** — The `scripts/shared/` package is the best-designed part of the codebase. `retry.py` with exponential backoff replaces bare `except` patterns. `api_budget.py` with SQLite-backed rolling-window quota tracking is exactly right for paid APIs. `config.py` with dot-notation YAML accessor is clean. `flame_client.py` with cache-first network-fallback-stale-fallback resolution is textbook graceful degradation. `llm_client.py` with model chain fallback and JSON fence-stripping centralizes what was previously duplicated across three AI scripts.

**Fingerprint engine** — The YAML-driven fingerprint definitions (`config/fingerprints/*.yaml`) with base confidence + modifiers + required indicators is an elegant pattern. It separates detection logic from code, making it easy to add new fingerprints without touching Python. The modifier system (delta scoring for GLEIF, VT, PhishTank, SecurityTrails matches) already does multi-source correlation at the fingerprint level — this is the right design.

**CI/CD pipeline** — The 4-job workflow (discovery → setup/shard → parallel process × 10 → finalize) is well-engineered. Artifact passing between jobs, `continue-on-error` for optional enrichments, timeout guards, and the shard-merge pattern handle the scale problem (230k+ domains) within GHA constraints.

**Data sharding for frontend** — `build_frontend_data.py` shards domains by first character for lazy loading. `DataContext.jsx` uses `useRef` for a shard cache with on-demand fetching. This is the right approach for serving 230k+ records from static JSON on GitHub Pages.

### Structural Issues

**No unified domain record** — Each enrichment script reads its own input, writes its own output. The "domain record" as a concept only comes together at two points: (1) the probed CSV (after infra/reputation/web enrichment) and (2) `build_frontend_data.py` (which merges a subset of optional files). But OpenSanctions, ICIJ, GLEIF, SecurityTrails, Whois, OpenClaw, and campaign hunt data all exist in separate files that only *partially* flow into the domain record.

**Pipeline ordering creates data loss** — The workflow runs enrichments in a fixed sequence, but some enrichments can't see the output of others. For example: `enrich_shodan.py` runs on `triage_candidates.csv` (post-triage), but its output `shodan_intelligence.csv` is copied to `docs/data/` directly — it's never merged back into `dea_domains_probed.csv`. Similarly, VT results go to `virustotal_intelligence.csv` but aren't merged into the main record. The fingerprint confidence modifiers reference `vt_malicious_count` and `st_registrar_changes`, but these fields only exist if the enrichment ran and the data was manually merged in a previous run.

**Recommendation: Introduce a domain enrichment registry** — A lightweight JSON or SQLite store (keyed by domain) that each enrichment script writes to, and that `build_frontend_data.py` reads from. This eliminates the fragmentation problem at the root. Every enrichment script does `registry.update(domain, {"shodan_ports": "80,443", ...})` and the frontend data builder reads the complete record.

---

## 2. Backend Pipeline Review

### Enrichment Scripts (Good)

`enrich_infrastructure.py`, `enrich_reputation.py`, `probe_web.py` — The core pipeline is solid. Async DNS resolution with worker pools, RBL checking, and HTTP/S probing with title extraction form a complete infrastructure fingerprint.

`enrich_opensanctions.py`, `enrich_icij.py`, `enrich_gleif.py` — Entity screening against sanctions lists, offshore leaks, and LEI registries is a differentiator. These correctly extract registrant org names and fuzzy-match against entity databases. The integration test coverage for these is strong.

`enrich_dnstwist.py` — Cross-referencing dnstwist permutation results against the live domain list to flag confirmed typosquats is clever. The `redirects_to_brand` field it produces is high-signal for FP-0007.

`match_fingerprints.py` — The matching engine correctly handles field aliases, four match types (exact, contains, regex, range), required vs optional indicators, and delta-based confidence scoring. Well-tested.

### Enrichment Scripts (Issues)

**`enrich_shodan.py` / `enrich_virustotal.py`** — Both write to standalone CSVs that aren't merged back into the main pipeline. The fingerprint YAML references `vt_malicious_count` and `shodan_` prefixed fields as confidence modifiers, but these fields may not exist in `dea_domains_probed.csv` if the enrichment ran after the probe step. **Fix:** Either merge Shodan/VT results back into probed CSV before fingerprinting, or restructure the finalize job ordering so fingerprint matching runs last.

**`triage_domains.py`** — Currently only uses text heuristics (keyword matching, Levenshtein distance, FLAME rule matching, fingerprint match status). It doesn't leverage the richer signals available post-enrichment: Shodan open ports, VT detection counts, PhishTank matches, OpenSanctions hits, GLEIF mismatches. Adding even a simple composite score from these signals would significantly improve triage precision.

**`ai_briefing.py`** — At 580 lines this is the most complex AI script. It generates the daily briefing consumed by `BriefingView.jsx`. The quality of the briefing depends entirely on what data it reads. Currently it reads probed CSV, fingerprint matches, triage candidates, Shodan data, and campaign hunt results. **Gap:** It doesn't read OpenSanctions/ICIJ/GLEIF entity screening results, VT intelligence, PhishTank matches, or OpenClaw shadow AI data. The briefing would be substantially richer if it consumed all enrichment outputs.

**`track_history.py`** — Only tracks aggregate daily stats (domain count, live count). Doesn't track per-domain lifecycle (first-seen, last-seen, infrastructure changes). This is a missed opportunity — temporal analysis ("this domain's MX changed from legitimate provider to bulletproof hosting 3 days ago") is often the highest-signal indicator.

### Data Files Not Reaching the Frontend

| Data Source | Pipeline Output | In Frontend? | Gap |
|---|---|---|---|
| Shodan | `shodan_intelligence.csv` | Partially (if merged) | Ports, vulns, OS not shown |
| VirusTotal | `virustotal_intelligence.csv` | No | Detection counts, engines not shown |
| PhishTank/URLhaus | `phishtank_matches.csv` | Partially (via optional merge) | Match URLs, threat type not prominent |
| OpenSanctions | Merged into probed CSV | Yes (EntityCard) | Working correctly |
| ICIJ | Merged into probed CSV | Yes (EntityCard) | Working correctly |
| GLEIF | Merged into probed CSV | Yes (EntityCard) | Working correctly |
| OpenClaw | `openclaw_exposed.csv` | No | Shadow AI agents not shown |
| Visual fingerprints | `visual_clusters.json`, screenshots | No | pHash clusters not in UI |
| Campaign hunts | `campaign_hunt_history.csv` | No | Campaign links not shown |
| SecurityTrails | `enriched_candidates.csv` | No | DNS history, registrar changes not shown |
| Whois (Port 43) | `domain_registrars.csv` | No | Registrar intel not in domain detail |
| Certificate Transparency | `discovered_certs.csv` | No | CT discoveries not linked |

**This table is the roadmap.** Every "No" row is data you're already collecting but not presenting to the analyst.

---

## 3. Frontend Review

### Architecture (Strong)

The React frontend is well-structured: `DataContext` with shard-based lazy loading, `react-router-dom` for navigation, `@tanstack/react-table` for the match dashboard, `sigma`/`graphology` for the cluster graph, `fuse.js` for search. The component decomposition (Layout, Section, Tooltip, ConfidenceBadge, FlameBadge, GlobalSearch) is clean. The dark theme with `Inter` + `JetBrains Mono` is professional. CSS custom properties for the design system are well-defined.

### Page-by-Page Assessment

**MatchDashboard** — Solid. Multi-select filters for FP ID, TLD, registrar work well. The `@tanstack/react-table` integration with sorting and pagination is correct. The FLAME TP badge integration gives cross-project context. **Missing:** No aggregate visualizations (distribution charts for FP types, TLD breakdown, confidence histogram). The KPI cards are static numbers — a trend sparkline showing day-over-day change would add temporal awareness.

**InvestigateLanding** — The letter/digit browse UI is a good UX pattern for static data. The shard loading with loading states works correctly. **Missing:** The search only navigates to a specific domain — it doesn't support partial or multi-domain search. No way to search by ASN, MX, IP, or registrar ("show me all domains on ASN 16276"). This is the single most requested feature for threat intelligence UIs.

**DomainDetail** — Shows DNS, Entity Screening (OpenSanctions/ICIJ/GLEIF), AI Classification, WHOIS, Web Probe, and Risk sections. The `EntityCard` component is a good pattern. **Missing:**
- No Shodan section (ports, vulns, services, OS)
- No VirusTotal section (detection ratio, engines, scan date)
- No PhishTank/URLhaus section (matched URLs, threat type)
- No OpenClaw section (shadow AI agent exposure)
- No screenshot display (visual fingerprint data exists)
- No related domains section ("other domains sharing this MX/IP/registrar")
- No timeline showing when enrichment data was collected

**ClusterView** — The sigma.js graph with ForceAtlas2 layout, neighbor highlighting, and the table↔graph toggle is well-implemented. The `buildSubgraph` function correctly extracts ego networks. **Missing:** No campaign-level clustering (by registrant email, SOA, SSL org — the Whoxy pivot data). No cluster overlap detection ("this MX host appears in 3 different fingerprint patterns"). No way to export a cluster as a STIX bundle.

**BriefingView** — The intelligence-community formatting (classification banner, BLUF, priority tags, confidence language highlighting) is strong and differentiated. Historical briefing navigation works. **Missing:** No charts or trend visualizations within the briefing. The briefing is entirely text — adding even a simple bar chart of top FP types or a map of ASN countries would make it more useful for executive consumption. Evidence candidates table should link to cluster view, not just individual domains.

### Frontend Component Gaps

**No risk score visualization** — Individual risk signals (RBL hits, OTX risk, VT malicious, PhishTank match, sanctions hit) exist across multiple sections. There's no composite risk score or radar/spider chart showing "this domain's aggregate risk profile." Adding a `RiskRadar` component to `DomainDetail` that maps normalized scores across 5-6 axes (reputation, infrastructure, entity, typosquat, AI classification) would immediately make the investigation experience more useful.

**No export functionality** — The UI is view-only. An analyst can't export a filtered match list, a domain investigation summary, or a cluster as STIX/CSV. Adding a `Download CSV` button to the match table and a `Export STIX` button to domain detail would make the tool operationally useful.

**No comparison mode** — Can't compare two domains side by side. This is a standard analyst workflow ("are these two domains part of the same campaign?").

**fpRegistry.js is static** — The fingerprint and threat path registries are hardcoded in `frontend/src/data/fpRegistry.js`. These should be generated by the build pipeline from `config/fingerprints/*.yaml` and the FLAME index, not manually maintained. Every time you add a fingerprint definition, you have to remember to update this file.

---

## 4. Data Connectivity Recommendations

These are ordered by impact-to-effort ratio:

### 4.1 — Merge ALL enrichment data into frontend (HIGH impact, MEDIUM effort)

Update `build_frontend_data.py` to merge these additional sources into the domain record:

```python
# Add to OPTIONAL_FILES dict
"shodan_intelligence": {
    "path": "data/shodan_intelligence.csv",
    "fields": ["ports", "vulns", "os", "tags", "hostnames"],
    "prefix": "shodan_",
},
"virustotal_intelligence": {
    "path": "data/virustotal_intelligence.csv",
    "fields": ["vt_malicious_count", "vt_undetected_count", "vt_last_analysis"],
    "prefix": "",  # fields already prefixed
},
"openclaw_exposed": {
    "path": "data/openclaw_exposed.csv",
    "fields": ["agent_type", "exposure_level", "model_id"],
    "prefix": "openclaw_",
},
"domain_registrars": {
    "path": "data/domain_registrars.csv",
    "fields": ["registrar", "creation_date", "expiration_date"],
    "prefix": "whois_",
},
```

Then add corresponding sections to `DomainDetail.jsx`. The Entity Screening pattern (`EntityCard`) already shows how to do this cleanly.

### 4.2 — Generate fpRegistry.js from YAML (HIGH impact, LOW effort)

Add a build step to `build_frontend_data.py` (or a new script) that reads `config/fingerprints/*.yaml` and outputs `frontend/src/data/fpRegistry.js`:

```python
def generate_fp_registry(fingerprint_dir, output_path):
    registry = {}
    for fp_file in glob.glob(os.path.join(fingerprint_dir, "*.yaml")):
        with open(fp_file) as f:
            fp = yaml.safe_load(f)
        registry[fp["id"]] = {
            "name": fp["name"],
            "description": fp.get("description", ""),
            "flame_tp_ids": fp.get("flame_tp_ids", []),
        }
    # Write as ES module
    with open(output_path, "w") as f:
        f.write(f"export const fpRegistry = {json.dumps(registry, indent=2)};\n")
```

This eliminates the manual sync between YAML fingerprints and frontend metadata.

### 4.3 — Add "Related Domains" to DomainDetail (HIGH impact, MEDIUM effort)

When viewing a domain, show other domains sharing the same infrastructure:

- Same primary MX → "X other domains use this MX"
- Same ASN + nameserver combo → "X other domains in this cluster"
- Same registrant org → "X other domains registered by this entity"

The data already exists in `clusters.json`. The frontend just needs to query it. In `DomainDetail.jsx`, add a section that finds the domain's cluster memberships and lists co-hosted domains with links.

### 4.4 — Pivot search from InvestigateLanding (HIGH impact, MEDIUM effort)

Add search-by-infrastructure to `InvestigateLanding.jsx`:

- "ASN:16276" → show all domains on that ASN
- "MX:temp-mail-pro.com" → show all domains using that MX
- "FP:FP-0001" → show all domains matching that fingerprint

This requires building a lightweight reverse index during `build_frontend_data.py`:

```python
# In build_frontend_data.py, generate an infra index
infra_index = {
    "asn": defaultdict(list),     # ASN -> [domains]
    "mx": defaultdict(list),      # MX host -> [domains]
    "registrar": defaultdict(list) # registrar -> [domains]
}
```

Write it to `docs/data/infra_index.json` and load it in `DataContext` for search.

### 4.5 — Composite risk score (MEDIUM impact, MEDIUM effort)

Add a `compute_risk_score()` function to `build_frontend_data.py` that normalizes and combines:

| Signal | Weight | Source |
|---|---|---|
| Fingerprint confidence (max across matches) | 25% | fingerprint_matches.csv |
| VT malicious count (normalized 0-100) | 20% | virustotal_intelligence.csv |
| OpenSanctions match score | 15% | probed CSV (os_match_score) |
| RBL hits count | 10% | probed CSV (rbl_hits) |
| PhishTank/URLhaus match | 10% | phishtank_matches.csv |
| AI typosquat confidence | 10% | ai_typosquats.csv |
| Domain age < 30 days | 10% | probed CSV (age_days) |

Output as `risk_score` (0-100) and `risk_level` (Critical/High/Medium/Low) in the domain record. Display as a colored badge in all table views and as a radar chart in `DomainDetail`.

### 4.6 — Visual fingerprint integration (MEDIUM impact, LOW effort)

Screenshots already exist in `data/screenshots/` and pHash clusters in `visual_clusters.json`. Add a "Visual" section to `DomainDetail.jsx` that shows the screenshot (if available) and lists visually similar domains from the same pHash cluster. This is a quick win — the data is already there.

### 4.7 — Temporal tracking per domain (HIGH impact, HIGH effort)

Extend `track_history.py` to maintain a per-domain changelog:

```json
{
  "example.com": {
    "first_seen": "2026-01-15",
    "last_seen": "2026-02-28",
    "changes": [
      {"date": "2026-02-10", "field": "primary_mx", "old": "mx1.legit.com", "new": "mx.bulletproof.ru"},
      {"date": "2026-02-20", "field": "http_status", "old": "200", "new": "403"}
    ]
  }
}
```

Store in `data/domain_history.json` (or SQLite for scale). Display as a timeline in `DomainDetail.jsx`. Infrastructure changes are often the highest-signal indicator of malicious activity.

---

## 5. Security Review

**Good:**
- CSV injection protection via `shared/sanitize.py` — correct implementation
- API keys managed via environment variables, never in code
- API budget tracking prevents accidental quota exhaustion
- `probe_web.py` uses identifiable User-Agent (`DomainIntelResearch/1.0`)
- STIX export uses proper `stix2` library, not hand-rolled JSON
- Workflow uses `secrets.*` for all sensitive values

**Watch:**
- `merge_lists_v3b.py` fetches from multiple external URLs (disposable-email lists). These are HTTP GETs to third-party repos. If any source is compromised, malicious domains could be injected into the allowlist. **Mitigation:** Add hash verification for known-good source snapshots, or at minimum log source URLs and response hashes.
- `enrich_infrastructure.py` with 200 async workers doing DNS resolution could trigger rate limiting or abuse complaints from upstream resolvers. The `cymru_resolver.py` has retry logic, but no global rate limiter across all concurrent workers.
- The `git push` at the end of the CI workflow uses `-X theirs` on rebase, which silently discards any conflicting manual commits. This is fine for fully-automated data files but risky if you ever manually edit files in `data/` or `docs/`.

---

## 6. Test Coverage Assessment

**Strong coverage (22 test files):**
- `test_fingerprints.py` — thorough testing of the matching engine
- `test_build_frontend_data.py` — comprehensive (21KB, the largest test file)
- `test_export_stix.py`, `test_flame_client.py`, `test_flame_regulatory.py` — good integration tests
- `test_gleif.py`, `test_icij.py`, `test_opensanctions.py` — entity screening well-tested
- `test_api_budget.py` — quota tracking edge cases covered
- `test_sanitize.py` — CSV injection protection tested

**Gaps:**
- No tests for `ai_briefing.py` — the most complex AI script has zero test coverage
- No tests for `triage_domains.py` — the prioritization logic that drives downstream enrichment
- No tests for `build_dashboard_data.py` (may be deprecated by `build_frontend_data.py`)
- No frontend tests (no `vitest`, `testing-library`, or Cypress in the project)
- No integration test that runs a mini-pipeline end-to-end (merge → enrich → fingerprint → build frontend data)

**Recommendation:** Prioritize tests for `ai_briefing.py` and `triage_domains.py` — these are high-impact scripts with complex logic and no safety net.

---

## 7. Priority Action Summary

| # | Action | Impact | Effort | Category |
|---|---|---|---|---|
| 1 | Merge all enrichment CSVs into frontend data builder | Critical | 3-4 hrs | Data connectivity |
| 2 | Add Shodan/VT/OpenClaw/screenshot sections to DomainDetail | Critical | 4-5 hrs | Frontend |
| 3 | Generate fpRegistry.js from YAML (eliminate manual sync) | High | 1 hr | Automation |
| 4 | Add "Related Domains" section to DomainDetail | High | 3 hrs | Frontend |
| 5 | Add infrastructure pivot search (ASN, MX, registrar) | High | 4 hrs | Frontend |
| 6 | Compute and display composite risk score | High | 3-4 hrs | Data + Frontend |
| 7 | Fix workflow ordering (Shodan/VT before fingerprinting) | High | 1 hr | Pipeline |
| 8 | Add visual fingerprint display to DomainDetail | Medium | 2 hrs | Frontend |
| 9 | Add export buttons (CSV, STIX) to UI | Medium | 3 hrs | Frontend |
| 10 | Implement per-domain temporal tracking | Medium | 6-8 hrs | Pipeline + Frontend |
| 11 | Feed all enrichment data into ai_briefing.py | Medium | 2-3 hrs | Pipeline |
| 12 | Add tests for ai_briefing.py and triage_domains.py | Medium | 3-4 hrs | Quality |
| 13 | Add trend sparklines to KPI cards (using history.json) | Low | 2 hrs | Frontend |
| 14 | Add domain comparison mode | Low | 4 hrs | Frontend |

**The first 6 items are the core "connect the data sources" work that would transform domain_intel from a good dashboard into a genuine analyst workbench.** They're all leveraging data you're already collecting — the investment is in surfacing it, not generating it.
