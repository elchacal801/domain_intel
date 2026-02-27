# Investigation Frontend & Data Transformer — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the vanilla JS dashboard with a 3-screen React investigation frontend and a Python data transformer that joins enrichment CSVs into optimized JSON files.

**Architecture:** Python script reads dea_domains_probed.csv + fingerprint_matches.csv + optional CSVs, computes infrastructure clusters, and writes 4 JSON files to docs/data/. React app (Vite + Tailwind + shadcn/ui) consumes those JSON files via HashRouter with three screens: /matches, /investigate/:domain, /clusters (Sigma.js graph).

**Tech Stack:** Python 3.10, React 19, Vite 7, Tailwind CSS 4, shadcn/ui, react-router-dom v7, @tanstack/react-table v8, Fuse.js, Sigma.js + graphology, ForceAtlas2

**Design Doc:** `docs/plans/2026-02-26-investigation-frontend-design.md`

---

## Task 1: Data Transformation Script — `scripts/build_frontend_data.py`

**Files:**
- Create: `scripts/build_frontend_data.py`
- Create: `tests/test_build_frontend_data.py`

**Step 1: Write failing tests**

Create `tests/test_build_frontend_data.py`:

```python
#!/usr/bin/env python3
"""Tests for build_frontend_data.py."""

import sys
import os
import csv
import json

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from build_frontend_data import (
    load_probed_csv,
    load_fingerprint_matches,
    compute_clusters,
    compute_stats,
    build_outputs,
)


def _write_csv(path, header, rows):
    """Helper to write a CSV test fixture."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for row in rows:
            w.writerow(row)


PROBED_HEADER = [
    "domain", "primary_mx", "mx_ip", "asn", "asn_name", "bgp_prefix", "cc",
    "registry", "mx_records", "nameservers", "risk_tags", "error", "rbl_hits",
    "creation_date", "age_days", "otx_risk", "registrant_org", "http_status",
    "http_title", "http_server", "https_status", "https_title", "https_server",
    "http_redirect_status", "http_redirect_target", "flame_tp_ids",
    "gleif_lei", "gleif_status", "gleif_legal_name", "gleif_jurisdiction",
    "gleif_has_parent", "os_match_score", "os_entity_type", "os_dataset",
    "os_entity_id", "icij_match_score", "icij_entity_match", "icij_dataset",
    "icij_jurisdiction", "dnstwist_match", "dnstwist_fuzzer", "dnstwist_target",
    "redirects_to_brand", "registrant_mismatch", "ssl_present",
]

FP_HEADER = ["domain", "fp_id", "fp_name", "confidence", "flame_tp_ids", "evidence"]


class TestLoadProbedCSV:
    def test_loads_rows_keyed_by_domain(self, tmp_path):
        csv_path = tmp_path / "probed.csv"
        _write_csv(csv_path, PROBED_HEADER, [
            ["evil.com", "mx.evil.com", "1.2.3.4", "16276", "OVH", "1.2.0.0/16",
             "FR", "RIPE", "mx.evil.com", "ns1.evil.com,ns2.evil.com", "HighRisk",
             "", "1", "2024-01-01", "365", "", "Evil Corp", "200", "Welcome",
             "nginx", "200", "Welcome", "nginx", "", "", "TP-0003",
             "", "", "", "", "", "85", "company", "sanctions", "Q123",
             "72", "Evil Corp Ltd", "pandora", "BVI",
             "", "", "", "", "", "true"],
        ])
        result = load_probed_csv(str(csv_path))
        assert "evil.com" in result
        assert result["evil.com"]["asn"] == "16276"
        assert result["evil.com"]["primary_mx"] == "mx.evil.com"

    def test_missing_file_returns_empty(self, tmp_path):
        result = load_probed_csv(str(tmp_path / "nonexistent.csv"))
        assert result == {}

    def test_empty_csv_returns_empty(self, tmp_path):
        csv_path = tmp_path / "empty.csv"
        _write_csv(csv_path, PROBED_HEADER, [])
        result = load_probed_csv(str(csv_path))
        assert result == {}


class TestLoadFingerprintMatches:
    def test_loads_and_groups_by_domain(self, tmp_path):
        csv_path = tmp_path / "fp.csv"
        _write_csv(csv_path, FP_HEADER, [
            ["evil.com", "FP-0001", "OVH cPanel", "85", "TP-0003", '{"asn":"16276"}'],
            ["evil.com", "FP-0006", "Shell MX", "70", "TP-0003", '{"mx":"shared"}'],
            ["other.com", "FP-0001", "OVH cPanel", "72", "TP-0003", '{}'],
        ])
        result = load_fingerprint_matches(str(csv_path))
        assert len(result["evil.com"]) == 2
        assert result["evil.com"][0]["fp_id"] == "FP-0001"
        assert len(result["other.com"]) == 1

    def test_missing_file_returns_empty(self, tmp_path):
        result = load_fingerprint_matches(str(tmp_path / "nope.csv"))
        assert result == {}


class TestComputeClusters:
    def test_groups_by_shared_mx(self):
        domains = {
            "a.com": {"primary_mx": "mx.shared.com", "mx_ip": "1.1.1.1",
                      "registrant_org": "A", "nameservers": "ns1.a.com"},
            "b.com": {"primary_mx": "mx.shared.com", "mx_ip": "2.2.2.2",
                      "registrant_org": "B", "nameservers": "ns1.b.com"},
            "c.com": {"primary_mx": "mx.shared.com", "mx_ip": "3.3.3.3",
                      "registrant_org": "C", "nameservers": "ns1.c.com"},
            "d.com": {"primary_mx": "mx.other.com", "mx_ip": "4.4.4.4",
                      "registrant_org": "D", "nameservers": "ns1.d.com"},
        }
        result = compute_clusters(domains, min_size=3)
        mx_nodes = [n for n in result["nodes"] if n["type"] == "mx_host"]
        assert any(n["label"] == "mx.shared.com" for n in mx_nodes)
        # d.com's MX only has 1 domain, so it should NOT appear
        assert not any(n["label"] == "mx.other.com" for n in mx_nodes)

    def test_groups_by_shared_ip(self):
        domains = {
            f"d{i}.com": {"primary_mx": f"mx{i}.com", "mx_ip": "1.2.3.4",
                          "registrant_org": f"Org{i}", "nameservers": f"ns{i}.com"}
            for i in range(4)
        }
        result = compute_clusters(domains, min_size=3)
        ip_nodes = [n for n in result["nodes"] if n["type"] == "ip"]
        assert any(n["label"] == "1.2.3.4" for n in ip_nodes)

    def test_groups_by_registrar_ns(self):
        domains = {
            f"d{i}.com": {"primary_mx": f"mx{i}.com", "mx_ip": f"10.0.0.{i}",
                          "registrant_org": "NameCheap", "nameservers": "ns1.nc.com,ns2.nc.com"}
            for i in range(3)
        }
        result = compute_clusters(domains, min_size=3)
        regns_nodes = [n for n in result["nodes"] if n["type"] == "registrar_ns"]
        assert len(regns_nodes) == 1

    def test_min_size_filter(self):
        # Only 2 domains share MX — below min_size=3
        domains = {
            "a.com": {"primary_mx": "mx.shared.com", "mx_ip": "1.1.1.1",
                      "registrant_org": "A", "nameservers": "ns1.a.com"},
            "b.com": {"primary_mx": "mx.shared.com", "mx_ip": "2.2.2.2",
                      "registrant_org": "B", "nameservers": "ns1.b.com"},
        }
        result = compute_clusters(domains, min_size=3)
        assert len(result["nodes"]) == 0
        assert len(result["edges"]) == 0

    def test_empty_fields_skipped(self):
        domains = {
            "a.com": {"primary_mx": "", "mx_ip": "", "registrant_org": "", "nameservers": ""},
            "b.com": {"primary_mx": "", "mx_ip": "", "registrant_org": "", "nameservers": ""},
            "c.com": {"primary_mx": "", "mx_ip": "", "registrant_org": "", "nameservers": ""},
        }
        result = compute_clusters(domains, min_size=3)
        assert len(result["nodes"]) == 0


class TestComputeStats:
    def test_basic_stats(self):
        domains = {"a.com": {"primary_mx": "mx"}, "b.com": {"primary_mx": "mx"}}
        fp_matches = {"a.com": [{"fp_id": "FP-0001"}]}
        clusters = {"nodes": [{"type": "mx_host"}], "edges": []}
        result = compute_stats(domains, fp_matches, clusters)
        assert result["total_domains"] == 2
        assert result["matched_domains"] == 1
        assert result["total_clusters"] == 1


class TestBuildOutputs:
    def test_writes_all_four_files(self, tmp_path):
        out_dir = tmp_path / "data"
        out_dir.mkdir()
        domains = {
            "evil.com": {
                "primary_mx": "mx.evil.com", "mx_ip": "1.2.3.4", "asn": "16276",
                "registrant_org": "Evil", "nameservers": "ns1.evil.com",
            }
        }
        fp_matches = {
            "evil.com": [{"fp_id": "FP-0001", "fp_name": "Test", "confidence": "85",
                          "flame_tp_ids": "TP-0003", "evidence": "{}"}]
        }
        build_outputs(domains, fp_matches, str(out_dir))

        assert (out_dir / "domains.json").exists()
        assert (out_dir / "fingerprint_matches.json").exists()
        assert (out_dir / "clusters.json").exists()
        assert (out_dir / "stats.json").exists()

        # Verify domains.json structure
        with open(out_dir / "domains.json") as f:
            d = json.load(f)
        assert "evil.com" in d
        assert d["evil.com"]["matches"][0]["fp_id"] == "FP-0001"

        # Verify fingerprint_matches.json is a flat list
        with open(out_dir / "fingerprint_matches.json") as f:
            fm = json.load(f)
        assert isinstance(fm, list)
        assert fm[0]["domain"] == "evil.com"
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_build_frontend_data.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'build_frontend_data'`

**Step 3: Implement `scripts/build_frontend_data.py`**

```python
#!/usr/bin/env python3
"""
build_frontend_data.py

Generates optimized JSON files for the investigation frontend from
enrichment CSVs. Replaces build_dashboard_data.py and build_investigate_index.py.

Reads:
  - data/dea_domains_probed.csv (required)
  - data/fingerprint_matches.csv (required)
  - data/ai_classifications.csv (optional)
  - data/ai_typosquats.csv (optional)
  - data/shodan_intelligence.csv (optional)
  - data/phishtank_matches.csv (optional)
  - data/openclaw_stix.json (optional)

Writes:
  - docs/data/domains.json
  - docs/data/fingerprint_matches.json
  - docs/data/clusters.json
  - docs/data/stats.json

Run after all enrichment and fingerprint matching steps in CI.
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def load_probed_csv(filepath):
    """Load dea_domains_probed.csv into a dict keyed by domain."""
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return {}

    domains = {}
    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get("domain", "").strip()
            if domain:
                domains[domain] = {k: v.strip() for k, v in row.items()}
    return domains


def load_fingerprint_matches(filepath):
    """Load fingerprint_matches.csv, grouped by domain."""
    if not os.path.exists(filepath):
        print(f"[!] Fingerprint matches not found: {filepath}")
        return {}

    matches = defaultdict(list)
    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get("domain", "").strip()
            if domain:
                matches[domain].append({
                    "fp_id": row.get("fp_id", "").strip(),
                    "fp_name": row.get("fp_name", "").strip(),
                    "confidence": row.get("confidence", "").strip(),
                    "flame_tp_ids": row.get("flame_tp_ids", "").strip(),
                    "evidence": row.get("evidence", "").strip(),
                })
    return dict(matches)


def _load_optional_csv(filepath, key_field="domain"):
    """Load an optional CSV, keyed by a field. Returns empty dict if missing."""
    if not os.path.exists(filepath):
        return {}
    result = {}
    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = row.get(key_field, "").strip()
            if key:
                result[key] = {k: v.strip() for k, v in row.items()}
    return result


def compute_clusters(domains, min_size=3):
    """
    Group domains by shared infrastructure.
    Returns {nodes: [...], edges: [...]}.
    Three cluster types: shared MX host, shared IP, shared registrar+NS.
    Only includes clusters with >= min_size domains.
    """
    # Build adjacency: infra_key -> set of domains
    infra_groups = defaultdict(set)

    for domain, data in domains.items():
        mx = data.get("primary_mx", "").strip()
        ip = data.get("mx_ip", "").strip()
        registrar = data.get("registrant_org", "").strip()
        ns = data.get("nameservers", "").strip()

        if mx:
            infra_groups[("mx_host", mx)].add(domain)
        if ip:
            infra_groups[("ip", ip)].add(domain)
        if registrar and ns:
            infra_groups[("registrar_ns", f"{registrar}|{ns}")].add(domain)

    # Filter by min_size and build graph
    nodes = []
    edges = []
    seen_domains = set()
    node_ids = set()

    for (infra_type, infra_value), domain_set in infra_groups.items():
        if len(domain_set) < min_size:
            continue

        # Infrastructure node
        infra_id = f"{infra_type}:{infra_value}"
        if infra_id not in node_ids:
            label = infra_value
            if infra_type == "registrar_ns":
                parts = infra_value.split("|", 1)
                label = f"{parts[0]} + {parts[1][:40]}" if len(parts) == 2 else infra_value
            nodes.append({
                "id": infra_id,
                "type": infra_type,
                "label": label,
                "size": min(5 + len(domain_set), 30),
            })
            node_ids.add(infra_id)

        # Domain nodes + edges
        for domain in domain_set:
            dom_id = f"dom:{domain}"
            if dom_id not in seen_domains:
                nodes.append({
                    "id": dom_id,
                    "type": "domain",
                    "label": domain,
                    "size": 3,
                })
                seen_domains.add(dom_id)
            edges.append({"source": dom_id, "target": infra_id})

    return {"nodes": nodes, "edges": edges}


def compute_stats(domains, fp_matches, clusters):
    """Compute summary statistics."""
    tld_counts = defaultdict(int)
    fp_counts = defaultdict(int)

    for domain in domains:
        parts = domain.rsplit(".", 1)
        tld = parts[-1] if len(parts) > 1 else "unknown"
        tld_counts[tld] += 1

    for domain, matches in fp_matches.items():
        for m in matches:
            fp_counts[m.get("fp_id", "")] += 1

    infra_nodes = [n for n in clusters.get("nodes", []) if n.get("type") != "domain"]

    return {
        "total_domains": len(domains),
        "matched_domains": len(fp_matches),
        "total_clusters": len(infra_nodes),
        "unique_fingerprints": len(fp_counts),
        "tld_distribution": dict(sorted(tld_counts.items(), key=lambda x: -x[1])[:20]),
        "top_fingerprints": dict(sorted(fp_counts.items(), key=lambda x: -x[1])[:10]),
        "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def build_outputs(domains, fp_matches, output_dir, min_cluster_size=3):
    """Build and write all 4 JSON output files."""
    os.makedirs(output_dir, exist_ok=True)

    # 1. Attach matches to domains and build domains.json
    for domain, matches in fp_matches.items():
        if domain in domains:
            domains[domain]["matches"] = matches

    # Ensure all domains have a matches key
    for domain in domains:
        if "matches" not in domains[domain]:
            domains[domain]["matches"] = []

    with open(os.path.join(output_dir, "domains.json"), "w", encoding="utf-8") as f:
        json.dump(domains, f, separators=(",", ":"), ensure_ascii=False)

    # 2. Build flat fingerprint_matches.json (for the match table)
    flat_matches = []
    for domain, matches in fp_matches.items():
        d_data = domains.get(domain, {})
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        for m in matches:
            flat_matches.append({
                "domain": domain,
                "fp_id": m["fp_id"],
                "fp_name": m["fp_name"],
                "confidence": m["confidence"],
                "flame_tp_ids": m["flame_tp_ids"],
                "evidence": m["evidence"],
                "tld": tld,
                "registrar": d_data.get("registrant_org", ""),
            })

    with open(os.path.join(output_dir, "fingerprint_matches.json"), "w", encoding="utf-8") as f:
        json.dump(flat_matches, f, separators=(",", ":"), ensure_ascii=False)

    # 3. Compute and write clusters.json
    clusters = compute_clusters(domains, min_size=min_cluster_size)
    with open(os.path.join(output_dir, "clusters.json"), "w", encoding="utf-8") as f:
        json.dump(clusters, f, separators=(",", ":"), ensure_ascii=False)

    # 4. Compute and write stats.json
    stats = compute_stats(domains, fp_matches, clusters)
    with open(os.path.join(output_dir, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print(f"[*] Frontend data written to {output_dir}/")
    print(f"    Domains: {stats['total_domains']:,}")
    print(f"    Matches: {stats['matched_domains']:,}")
    print(f"    Clusters: {stats['total_clusters']}")


def main():
    parser = argparse.ArgumentParser(description="Build frontend JSON data files")
    parser.add_argument("--probed", default="data/dea_domains_probed.csv",
                        help="Path to dea_domains_probed.csv")
    parser.add_argument("--fingerprints", default="data/fingerprint_matches.csv",
                        help="Path to fingerprint_matches.csv")
    parser.add_argument("--output-dir", default="docs/data",
                        help="Output directory for JSON files")
    parser.add_argument("--min-cluster-size", type=int, default=3,
                        help="Minimum domains per cluster (default: 3)")
    args = parser.parse_args()

    # Required files
    if not os.path.exists(args.probed):
        print(f"[!] Required file missing: {args.probed}")
        sys.exit(1)
    if not os.path.exists(args.fingerprints):
        print(f"[!] Required file missing: {args.fingerprints}")
        sys.exit(1)

    # Load data
    print("[*] Loading probed domains...")
    domains = load_probed_csv(args.probed)
    print(f"    Loaded {len(domains):,} domains")

    print("[*] Loading fingerprint matches...")
    fp_matches = load_fingerprint_matches(args.fingerprints)
    print(f"    Loaded matches for {len(fp_matches):,} domains")

    # Optional: merge AI classifications
    ai_class = _load_optional_csv("data/ai_classifications.csv")
    for domain, data in ai_class.items():
        if domain in domains:
            domains[domain]["ai_classification"] = data.get("classification", "")
            domains[domain]["ai_confidence"] = data.get("confidence", "")

    # Optional: merge AI typosquats
    ai_typo = _load_optional_csv("data/ai_typosquats.csv")
    for domain, data in ai_typo.items():
        if domain in domains:
            domains[domain]["ai_typosquat_target"] = data.get("target", "")

    # Optional: merge Shodan
    shodan = _load_optional_csv("data/shodan_intelligence.csv")
    for domain, data in shodan.items():
        if domain in domains:
            domains[domain]["shodan_ports"] = data.get("ports", "")
            domains[domain]["shodan_vulns"] = data.get("vulns", "")

    # Optional: merge PhishTank
    phish = _load_optional_csv("data/phishtank_matches.csv")
    for domain, data in phish.items():
        if domain in domains:
            domains[domain]["phishtank_url"] = data.get("url", "")
            domains[domain]["phishtank_target"] = data.get("target", "")

    # Build outputs
    build_outputs(domains, fp_matches, args.output_dir, args.min_cluster_size)


if __name__ == "__main__":
    main()
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_build_frontend_data.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add scripts/build_frontend_data.py tests/test_build_frontend_data.py
git commit -m "feat: add build_frontend_data.py data transformer with tests"
```

---

## Task 2: React App Scaffold

**Files:**
- Modify: `frontend/package.json`
- Replace: `frontend/vite.config.js`
- Create: `frontend/index.html` (replace existing)
- Create: `frontend/src/main.jsx`
- Create: `frontend/src/App.jsx`
- Create: `frontend/src/index.css`
- Create: `frontend/src/context/DataContext.jsx`
- Create: `frontend/src/components/Layout.jsx`
- Create: `frontend/src/components/GlobalSearch.jsx`
- Delete: `frontend/src/main.js`, `frontend/src/data.js`, `frontend/src/charts.js`, `frontend/src/investigate.js`
- Delete: `docs/app.js`, `docs/index.html`, `docs/assets/` (old build output)

**Step 1: Clean up old frontend files**

```bash
# Remove old vanilla JS source files
rm frontend/src/main.js frontend/src/data.js frontend/src/charts.js frontend/src/investigate.js
# Remove old build output (will be replaced by React build)
rm docs/index.html docs/app.js
rm -rf docs/assets/
```

**Step 2: Initialize React + Tailwind + dependencies**

Replace `frontend/package.json`:

```json
{
  "name": "domain-intel-frontend",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^19.1.0",
    "react-dom": "^19.1.0",
    "react-router-dom": "^7.5.0",
    "@tanstack/react-table": "^8.21.0",
    "fuse.js": "^7.1.0",
    "sigma": "^3.0.0",
    "graphology": "^0.26.0",
    "graphology-layout-forceatlas2": "^0.10.1",
    "lucide-react": "^0.475.0",
    "clsx": "^2.1.1",
    "tailwind-merge": "^3.0.0",
    "class-variance-authority": "^0.7.1"
  },
  "devDependencies": {
    "vite": "^7.3.1",
    "@vitejs/plugin-react": "^4.4.1",
    "tailwindcss": "^4.1.0",
    "@tailwindcss/vite": "^4.1.0"
  }
}
```

Run: `cd frontend && npm install`

**Step 3: Update `frontend/vite.config.js`**

```javascript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { resolve } from 'path';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: './',
  server: {
    port: 3000,
    fs: { allow: ['..'] },
  },
  build: {
    outDir: '../docs',
    emptyOutDir: false,  // preserve docs/data/
    rollupOptions: {
      input: resolve(__dirname, 'index.html'),
    },
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
});
```

Note: `emptyOutDir: false` is critical — it prevents Vite from deleting docs/data/ during build.

**Step 4: Create `frontend/index.html`**

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Domain Intelligence | Investigation</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔍</text></svg>" />
  </head>
  <body class="min-h-screen bg-gray-950 text-gray-100">
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
```

**Step 5: Create `frontend/src/index.css`**

```css
@import "tailwindcss";

@theme {
  --color-surface: #111827;
  --color-surface-raised: #1f2937;
  --color-border-subtle: #374151;
  --color-confidence-low: #22c55e;
  --color-confidence-med: #eab308;
  --color-confidence-high: #ef4444;
  --color-mx: #3b82f6;
  --color-ip: #f97316;
  --color-regns: #22c55e;
}
```

**Step 6: Create `frontend/src/lib/utils.js`** (shadcn/ui utility)

```javascript
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs) {
  return twMerge(clsx(inputs));
}
```

**Step 7: Create `frontend/src/context/DataContext.jsx`**

```jsx
import { createContext, useContext, useState, useEffect, useCallback } from 'react';

const DataContext = createContext(null);

export function DataProvider({ children }) {
  const [stats, setStats] = useState(null);
  const [fpMatches, setFpMatches] = useState(null);
  const [clusters, setClusters] = useState(null);
  const [domains, setDomains] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadInitialData() {
      try {
        const [statsRes, fpRes, clustersRes] = await Promise.all([
          fetch('./data/stats.json').then(r => r.ok ? r.json() : null),
          fetch('./data/fingerprint_matches.json').then(r => r.ok ? r.json() : null),
          fetch('./data/clusters.json').then(r => r.ok ? r.json() : null),
        ]);
        setStats(statsRes);
        setFpMatches(fpRes || []);
        setClusters(clustersRes || { nodes: [], edges: [] });
      } catch (err) {
        console.error('Failed to load data:', err);
      } finally {
        setLoading(false);
      }
    }
    loadInitialData();
  }, []);

  const loadDomains = useCallback(async () => {
    if (domains) return domains;
    try {
      const res = await fetch('./data/domains.json');
      if (!res.ok) return {};
      const data = await res.json();
      setDomains(data);
      return data;
    } catch {
      return {};
    }
  }, [domains]);

  return (
    <DataContext.Provider value={{ stats, fpMatches, clusters, domains, loadDomains, loading }}>
      {children}
    </DataContext.Provider>
  );
}

export function useData() {
  const ctx = useContext(DataContext);
  if (!ctx) throw new Error('useData must be used within DataProvider');
  return ctx;
}
```

**Step 8: Create `frontend/src/components/GlobalSearch.jsx`**

```jsx
import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import Fuse from 'fuse.js';
import { useData } from '@/context/DataContext';

export default function GlobalSearch() {
  const { fpMatches } = useData();
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const fuseRef = useRef(null);

  useEffect(() => {
    if (fpMatches && fpMatches.length > 0) {
      // Dedupe domains for search index
      const seen = new Set();
      const items = fpMatches.filter(m => {
        if (seen.has(m.domain)) return false;
        seen.add(m.domain);
        return true;
      });
      fuseRef.current = new Fuse(items, {
        keys: ['domain', 'fp_name'],
        threshold: 0.3,
      });
    }
  }, [fpMatches]);

  useEffect(() => {
    function handleClickOutside(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  function handleSearch(value) {
    setQuery(value);
    if (!value.trim() || !fuseRef.current) {
      setResults([]);
      setOpen(false);
      return;
    }
    const hits = fuseRef.current.search(value).slice(0, 10);
    setResults(hits.map(h => h.item));
    setOpen(true);
  }

  function handleSelect(domain) {
    setQuery('');
    setOpen(false);
    navigate(`/investigate/${domain}`);
  }

  function handleKeyDown(e) {
    if (e.key === 'Enter' && query.trim()) {
      setOpen(false);
      navigate(`/investigate/${query.trim()}`);
    }
  }

  return (
    <div ref={ref} className="relative">
      <input
        type="text"
        value={query}
        onChange={e => handleSearch(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="Search domains..."
        className="w-64 rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm text-gray-100 placeholder-gray-500 focus:border-blue-500 focus:outline-none"
      />
      {open && results.length > 0 && (
        <div className="absolute top-full left-0 z-50 mt-1 w-80 rounded-md border border-border-subtle bg-surface-raised shadow-lg">
          {results.map(r => (
            <button
              key={r.domain}
              onClick={() => handleSelect(r.domain)}
              className="block w-full px-3 py-2 text-left text-sm hover:bg-gray-700"
            >
              <span className="font-mono">{r.domain}</span>
              <span className="ml-2 text-xs text-gray-400">{r.fp_name}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
```

**Step 9: Create `frontend/src/components/Layout.jsx`**

```jsx
import { NavLink, Outlet } from 'react-router-dom';
import GlobalSearch from './GlobalSearch';
import { useData } from '@/context/DataContext';

const NAV_ITEMS = [
  { to: '/matches', label: 'Matches' },
  { to: '/investigate', label: 'Investigate' },
  { to: '/clusters', label: 'Clusters' },
];

export default function Layout() {
  const { loading } = useData();

  return (
    <div className="min-h-screen bg-gray-950">
      <nav className="border-b border-border-subtle bg-surface">
        <div className="mx-auto flex max-w-screen-2xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-6">
            <span className="text-lg font-bold text-gray-100">Domain Intel</span>
            <div className="flex gap-1">
              {NAV_ITEMS.map(item => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                      isActive
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
                    }`
                  }
                >
                  {item.label}
                </NavLink>
              ))}
            </div>
          </div>
          <GlobalSearch />
        </div>
      </nav>
      <main className="mx-auto max-w-screen-2xl p-4">
        {loading ? (
          <div className="flex h-64 items-center justify-center">
            <div className="text-gray-400">Loading data...</div>
          </div>
        ) : (
          <Outlet />
        )}
      </main>
    </div>
  );
}
```

**Step 10: Create `frontend/src/App.jsx`**

```jsx
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { DataProvider } from '@/context/DataContext';
import Layout from '@/components/Layout';
import MatchDashboard from '@/pages/MatchDashboard';
import InvestigateLanding from '@/pages/InvestigateLanding';
import DomainDetail from '@/pages/DomainDetail';
import ClusterView from '@/pages/ClusterView';

export default function App() {
  return (
    <HashRouter>
      <DataProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Navigate to="/matches" replace />} />
            <Route path="matches" element={<MatchDashboard />} />
            <Route path="investigate" element={<InvestigateLanding />} />
            <Route path="investigate/:domain" element={<DomainDetail />} />
            <Route path="clusters" element={<ClusterView />} />
          </Route>
        </Routes>
      </DataProvider>
    </HashRouter>
  );
}
```

**Step 11: Create `frontend/src/main.jsx`**

```jsx
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './index.css';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>
);
```

**Step 12: Create placeholder pages** (just enough to verify routing)

Create `frontend/src/pages/MatchDashboard.jsx`:
```jsx
export default function MatchDashboard() {
  return <div className="text-gray-400">Match Dashboard — coming next</div>;
}
```

Create `frontend/src/pages/InvestigateLanding.jsx`:
```jsx
export default function InvestigateLanding() {
  return (
    <div className="flex h-64 items-center justify-center text-gray-500">
      Search for a domain above to investigate
    </div>
  );
}
```

Create `frontend/src/pages/DomainDetail.jsx`:
```jsx
import { useParams } from 'react-router-dom';
export default function DomainDetail() {
  const { domain } = useParams();
  return <div className="text-gray-400">Investigating: {domain}</div>;
}
```

Create `frontend/src/pages/ClusterView.jsx`:
```jsx
export default function ClusterView() {
  return <div className="text-gray-400">Cluster View — coming soon</div>;
}
```

**Step 13: Verify the scaffold builds**

Run: `cd frontend && npm run build`
Expected: Build succeeds, writes index.html + assets/ to `docs/`

**Step 14: Commit**

```bash
git add frontend/ docs/index.html docs/assets/
git rm docs/app.js  # remove old vanilla JS
git commit -m "feat: scaffold React + Tailwind + shadcn/ui frontend with routing"
```

---

## Task 3: Screen 1 — Domain Investigation View (`/investigate/:domain`)

**Files:**
- Rewrite: `frontend/src/pages/DomainDetail.jsx`
- Create: `frontend/src/components/ConfidenceBadge.jsx`
- Create: `frontend/src/components/FlameBadge.jsx`
- Create: `frontend/src/components/Section.jsx`

**Step 1: Create shared UI components**

`frontend/src/components/ConfidenceBadge.jsx`:
```jsx
import { cn } from '@/lib/utils';

export default function ConfidenceBadge({ score }) {
  const num = parseInt(score, 10) || 0;
  const color = num > 75 ? 'bg-red-600' : num > 50 ? 'bg-yellow-600' : 'bg-green-600';
  return (
    <span className={cn('inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium text-white', color)}>
      {num}%
    </span>
  );
}
```

`frontend/src/components/FlameBadge.jsx`:
```jsx
export default function FlameBadge({ tp }) {
  return (
    <span className="inline-flex items-center rounded-full bg-orange-900/50 border border-orange-700 px-2 py-0.5 text-xs font-mono text-orange-300">
      {tp}
    </span>
  );
}
```

`frontend/src/components/Section.jsx`:
```jsx
export default function Section({ title, children, className = '' }) {
  return (
    <div className={`rounded-lg border border-border-subtle bg-surface-raised p-4 ${className}`}>
      <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-gray-400">{title}</h3>
      {children}
    </div>
  );
}
```

**Step 2: Implement `DomainDetail.jsx`**

```jsx
import { useParams, Link } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { useData } from '@/context/DataContext';
import ConfidenceBadge from '@/components/ConfidenceBadge';
import FlameBadge from '@/components/FlameBadge';
import Section from '@/components/Section';

function Field({ label, value }) {
  if (!value) return null;
  return (
    <div>
      <dt className="text-xs text-gray-500">{label}</dt>
      <dd className="font-mono text-sm text-gray-200">{value}</dd>
    </div>
  );
}

function MatchCard({ match }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="rounded border border-border-subtle bg-gray-900 p-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm text-blue-400">{match.fp_id}</span>
          <span className="text-sm text-gray-300">{match.fp_name}</span>
          <ConfidenceBadge score={match.confidence} />
        </div>
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-xs text-gray-500 hover:text-gray-300"
        >
          {expanded ? 'Hide' : 'Show'} evidence
        </button>
      </div>
      {expanded && match.evidence && (
        <pre className="mt-2 overflow-x-auto rounded bg-gray-950 p-2 text-xs text-gray-400">
          {(() => {
            try { return JSON.stringify(JSON.parse(match.evidence), null, 2); }
            catch { return match.evidence; }
          })()}
        </pre>
      )}
    </div>
  );
}

export default function DomainDetail() {
  const { domain } = useParams();
  const { loadDomains, domains } = useData();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      setLoading(true);
      const allDomains = domains || await loadDomains();
      setData(allDomains[domain] || null);
      setLoading(false);
    }
    load();
  }, [domain, loadDomains, domains]);

  if (loading) return <div className="text-gray-400 p-8">Loading domain data...</div>;
  if (!data) return <div className="text-gray-400 p-8">Domain not found: {domain}</div>;

  const tps = (data.flame_tp_ids || '').split(',').filter(Boolean);
  const matches = data.matches || [];
  const topConfidence = matches.length > 0
    ? Math.max(...matches.map(m => parseInt(m.confidence, 10) || 0))
    : null;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold font-mono text-gray-100">{domain}</h1>
        {topConfidence !== null && <ConfidenceBadge score={topConfidence} />}
        {tps.map(tp => <FlameBadge key={tp} tp={tp.trim()} />)}
      </div>

      {/* Fingerprint Matches */}
      {matches.length > 0 && (
        <Section title="Fingerprint Matches">
          <div className="space-y-2">
            {matches.map((m, i) => <MatchCard key={i} match={m} />)}
          </div>
        </Section>
      )}

      {/* Entity Screening */}
      {(data.os_match_score || data.icij_match_score || data.gleif_lei) && (
        <Section title="Entity Screening">
          <div className="grid gap-4 sm:grid-cols-3">
            {data.os_match_score && (
              <div className="rounded border border-border-subtle p-3">
                <h4 className="text-xs font-semibold text-red-400">OpenSanctions</h4>
                <dl className="mt-2 space-y-1">
                  <Field label="Match Score" value={data.os_match_score} />
                  <Field label="Entity Type" value={data.os_entity_type} />
                  <Field label="Dataset" value={data.os_dataset} />
                  <Field label="Entity ID" value={data.os_entity_id} />
                </dl>
              </div>
            )}
            {data.icij_match_score && (
              <div className="rounded border border-border-subtle p-3">
                <h4 className="text-xs font-semibold text-yellow-400">ICIJ OffshoreLeaks</h4>
                <dl className="mt-2 space-y-1">
                  <Field label="Match Score" value={data.icij_match_score} />
                  <Field label="Entity" value={data.icij_entity_match} />
                  <Field label="Dataset" value={data.icij_dataset} />
                  <Field label="Jurisdiction" value={data.icij_jurisdiction} />
                </dl>
              </div>
            )}
            {data.gleif_lei && (
              <div className="rounded border border-border-subtle p-3">
                <h4 className="text-xs font-semibold text-green-400">GLEIF</h4>
                <dl className="mt-2 space-y-1">
                  <Field label="LEI" value={data.gleif_lei} />
                  <Field label="Status" value={data.gleif_status} />
                  <Field label="Legal Name" value={data.gleif_legal_name} />
                  <Field label="Jurisdiction" value={data.gleif_jurisdiction} />
                </dl>
              </div>
            )}
          </div>
        </Section>
      )}

      {/* DNS Infrastructure */}
      <Section title="DNS Infrastructure">
        <dl className="grid gap-x-8 gap-y-2 sm:grid-cols-3">
          <Field label="Primary MX" value={data.primary_mx} />
          <Field label="MX IP" value={data.mx_ip} />
          <Field label="ASN" value={data.asn ? `${data.asn} (${data.asn_name || ''})` : null} />
          <Field label="BGP Prefix" value={data.bgp_prefix} />
          <Field label="Nameservers" value={data.nameservers} />
          <Field label="Country" value={data.cc} />
          <Field label="MX Records" value={data.mx_records} />
        </dl>
      </Section>

      {/* AI Classification */}
      {(data.ai_classification || data.dnstwist_match) && (
        <Section title="AI Classification">
          <dl className="grid gap-x-8 gap-y-2 sm:grid-cols-2">
            <Field label="Classification" value={data.ai_classification} />
            <Field label="AI Confidence" value={data.ai_confidence} />
            <Field label="Typosquat Match" value={data.dnstwist_match} />
            <Field label="Fuzzer" value={data.dnstwist_fuzzer} />
            <Field label="Target Brand" value={data.dnstwist_target} />
            <Field label="Redirects to Brand" value={data.redirects_to_brand} />
          </dl>
        </Section>
      )}

      {/* WHOIS / RDAP */}
      <Section title="WHOIS / RDAP">
        <dl className="grid gap-x-8 gap-y-2 sm:grid-cols-3">
          <Field label="Registrant Org" value={data.registrant_org} />
          <Field label="Creation Date" value={data.creation_date} />
          <Field label="Age (days)" value={data.age_days} />
          <Field label="Registry" value={data.registry} />
          <Field label="SSL Present" value={data.ssl_present} />
          <Field label="Registrant Mismatch" value={data.registrant_mismatch} />
        </dl>
      </Section>

      {/* Web Probe */}
      <Section title="Web Probe">
        <dl className="grid gap-x-8 gap-y-2 sm:grid-cols-3">
          <Field label="HTTP Status" value={data.http_status} />
          <Field label="HTTP Title" value={data.http_title} />
          <Field label="HTTP Server" value={data.http_server} />
          <Field label="HTTPS Status" value={data.https_status} />
          <Field label="HTTPS Title" value={data.https_title} />
          <Field label="HTTPS Server" value={data.https_server} />
          <Field label="Redirect Target" value={data.http_redirect_target} />
        </dl>
      </Section>

      {/* Risk & Reputation */}
      {(data.risk_tags || data.rbl_hits || data.otx_risk) && (
        <Section title="Risk & Reputation">
          <dl className="grid gap-x-8 gap-y-2 sm:grid-cols-2">
            <Field label="Risk Tags" value={data.risk_tags} />
            <Field label="RBL Hits" value={data.rbl_hits} />
            <Field label="OTX Risk" value={data.otx_risk} />
          </dl>
        </Section>
      )}
    </div>
  );
}
```

**Step 3: Verify build**

Run: `cd frontend && npm run build`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add frontend/src/
git commit -m "feat: add domain investigation view with all enrichment sections"
```

---

## Task 4: Screen 2 — Fingerprint Match Dashboard (`/matches`)

**Files:**
- Rewrite: `frontend/src/pages/MatchDashboard.jsx`

**Step 1: Implement `MatchDashboard.jsx`**

```jsx
import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  flexRender,
  createColumnHelper,
} from '@tanstack/react-table';
import { useData } from '@/context/DataContext';
import ConfidenceBadge from '@/components/ConfidenceBadge';
import FlameBadge from '@/components/FlameBadge';

const columnHelper = createColumnHelper();

function MultiSelectFilter({ label, options, selected, onChange }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm text-gray-300"
      >
        {label} {selected.length > 0 && `(${selected.length})`}
      </button>
      {open && (
        <div className="absolute top-full left-0 z-50 mt-1 max-h-60 w-56 overflow-y-auto rounded-md border border-border-subtle bg-surface-raised shadow-lg">
          {options.map(opt => (
            <label key={opt} className="flex items-center gap-2 px-3 py-1.5 text-sm hover:bg-gray-700 cursor-pointer">
              <input
                type="checkbox"
                checked={selected.includes(opt)}
                onChange={() => {
                  onChange(selected.includes(opt)
                    ? selected.filter(s => s !== opt)
                    : [...selected, opt]
                  );
                }}
                className="rounded"
              />
              <span className="text-gray-300 truncate">{opt}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

export default function MatchDashboard() {
  const { fpMatches, stats } = useData();
  const navigate = useNavigate();
  const [sorting, setSorting] = useState([]);
  const [fpFilter, setFpFilter] = useState([]);
  const [tldFilter, setTldFilter] = useState([]);
  const [regFilter, setRegFilter] = useState([]);
  const [search, setSearch] = useState('');

  const fpIds = useMemo(() => [...new Set((fpMatches || []).map(m => m.fp_id))].sort(), [fpMatches]);
  const tlds = useMemo(() => [...new Set((fpMatches || []).map(m => m.tld))].sort(), [fpMatches]);
  const registrars = useMemo(() =>
    [...new Set((fpMatches || []).map(m => m.registrar).filter(Boolean))].sort(),
    [fpMatches]
  );

  const filtered = useMemo(() => {
    let data = fpMatches || [];
    if (fpFilter.length) data = data.filter(m => fpFilter.includes(m.fp_id));
    if (tldFilter.length) data = data.filter(m => tldFilter.includes(m.tld));
    if (regFilter.length) data = data.filter(m => regFilter.includes(m.registrar));
    if (search) data = data.filter(m => m.domain.includes(search.toLowerCase()));
    return data;
  }, [fpMatches, fpFilter, tldFilter, regFilter, search]);

  const columns = useMemo(() => [
    columnHelper.accessor('domain', {
      header: 'Domain',
      cell: info => <span className="font-mono text-blue-400">{info.getValue()}</span>,
    }),
    columnHelper.accessor('fp_id', {
      header: 'Fingerprint',
      cell: info => <span className="font-mono text-xs">{info.getValue()}</span>,
    }),
    columnHelper.accessor('confidence', {
      header: 'Confidence',
      cell: info => <ConfidenceBadge score={info.getValue()} />,
      sortingFn: (a, b) => parseInt(a.original.confidence) - parseInt(b.original.confidence),
    }),
    columnHelper.accessor('flame_tp_ids', {
      header: 'FLAME TPs',
      cell: info => {
        const tps = (info.getValue() || '').split(',').filter(Boolean);
        return <div className="flex gap-1">{tps.map(tp => <FlameBadge key={tp} tp={tp.trim()} />)}</div>;
      },
    }),
    columnHelper.accessor('tld', { header: 'TLD' }),
    columnHelper.accessor('registrar', {
      header: 'Registrar',
      cell: info => <span className="text-xs truncate max-w-[150px] block">{info.getValue()}</span>,
    }),
  ], []);

  const table = useReactTable({
    data: filtered,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 50 } },
  });

  return (
    <div className="space-y-4">
      {/* Stats bar */}
      {stats && (
        <div className="grid grid-cols-4 gap-4">
          {[
            ['Total Domains', stats.total_domains?.toLocaleString()],
            ['FP Matches', stats.matched_domains?.toLocaleString()],
            ['Unique FPs', stats.unique_fingerprints],
            ['Clusters', stats.total_clusters],
          ].map(([label, value]) => (
            <div key={label} className="rounded-lg border border-border-subtle bg-surface-raised p-4">
              <div className="text-2xl font-bold text-gray-100">{value || 0}</div>
              <div className="text-xs text-gray-500">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter by domain..."
          className="rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm text-gray-100 placeholder-gray-500"
        />
        <MultiSelectFilter label="Fingerprint" options={fpIds} selected={fpFilter} onChange={setFpFilter} />
        <MultiSelectFilter label="TLD" options={tlds} selected={tldFilter} onChange={setTldFilter} />
        <MultiSelectFilter label="Registrar" options={registrars} selected={regFilter} onChange={setRegFilter} />
        {(fpFilter.length > 0 || tldFilter.length > 0 || regFilter.length > 0 || search) && (
          <button
            onClick={() => { setFpFilter([]); setTldFilter([]); setRegFilter([]); setSearch(''); }}
            className="text-xs text-gray-500 hover:text-gray-300"
          >
            Clear filters
          </button>
        )}
        <span className="ml-auto text-xs text-gray-500">{filtered.length} results</span>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-border-subtle">
        <table className="w-full text-sm">
          <thead className="bg-surface text-left text-xs uppercase text-gray-500">
            {table.getHeaderGroups().map(hg => (
              <tr key={hg.id}>
                {hg.headers.map(header => (
                  <th
                    key={header.id}
                    onClick={header.column.getToggleSortingHandler()}
                    className="cursor-pointer px-4 py-3 hover:text-gray-300"
                  >
                    {flexRender(header.column.columnDef.header, header.getContext())}
                    {{ asc: ' ↑', desc: ' ↓' }[header.column.getIsSorted()] ?? ''}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map(row => (
              <tr
                key={row.id}
                onClick={() => navigate(`/investigate/${row.original.domain}`)}
                className="cursor-pointer border-t border-border-subtle hover:bg-gray-800/50"
              >
                {row.getVisibleCells().map(cell => (
                  <td key={cell.id} className="px-4 py-2">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm text-gray-500">
        <span>
          Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
        </span>
        <div className="flex gap-2">
          <button onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}
            className="rounded border border-border-subtle px-3 py-1 disabled:opacity-30">
            Previous
          </button>
          <button onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}
            className="rounded border border-border-subtle px-3 py-1 disabled:opacity-30">
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
```

**Step 2: Verify build**

Run: `cd frontend && npm run build`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add frontend/src/pages/MatchDashboard.jsx
git commit -m "feat: add fingerprint match dashboard with sorting, filtering, pagination"
```

---

## Task 5: Screen 3 — Cluster Visualization (`/clusters`)

**Files:**
- Rewrite: `frontend/src/pages/ClusterView.jsx`
- Create: `frontend/src/components/SigmaGraph.jsx`

**Step 1: Create `frontend/src/components/SigmaGraph.jsx`**

```jsx
import { useEffect, useRef, useCallback } from 'react';
import Graph from 'graphology';
import Sigma from 'sigma';
import forceAtlas2 from 'graphology-layout-forceatlas2';

const TYPE_COLORS = {
  mx_host: '#3b82f6',
  ip: '#f97316',
  registrar_ns: '#22c55e',
  domain: '#94a3b8',
};

export default function SigmaGraph({ data, onClickNode, filters }) {
  const containerRef = useRef(null);
  const sigmaRef = useRef(null);
  const graphRef = useRef(null);

  const buildGraph = useCallback(() => {
    if (!data || !data.nodes) return null;
    const graph = new Graph();

    const filteredNodes = new Set();
    for (const node of data.nodes) {
      if (node.type === 'domain') continue; // add domains via edges
      if (filters?.types && !filters.types.includes(node.type)) continue;
      filteredNodes.add(node.id);
    }

    // Add infra nodes
    for (const node of data.nodes) {
      if (!filteredNodes.has(node.id) && node.type !== 'domain') continue;
      if (node.type === 'domain') continue;
      graph.addNode(node.id, {
        label: node.label,
        size: node.size,
        color: TYPE_COLORS[node.type] || '#94a3b8',
        type: node.type,
        x: Math.random() * 100,
        y: Math.random() * 100,
      });
    }

    // Add edges and domain nodes (only if connected to visible infra)
    const domainNodes = new Set();
    for (const edge of data.edges) {
      if (!graph.hasNode(edge.target)) continue;
      if (!domainNodes.has(edge.source)) {
        const domNode = data.nodes.find(n => n.id === edge.source);
        if (domNode) {
          graph.addNode(edge.source, {
            label: domNode.label,
            size: 3,
            color: TYPE_COLORS.domain,
            type: 'domain',
            x: Math.random() * 100,
            y: Math.random() * 100,
          });
          domainNodes.add(edge.source);
        }
      }
      if (graph.hasNode(edge.source)) {
        graph.addEdge(edge.source, edge.target, { color: '#374151', size: 0.5 });
      }
    }

    // Apply min-size filter
    if (filters?.minSize) {
      const infraToRemove = [];
      graph.forEachNode((nodeId, attrs) => {
        if (attrs.type !== 'domain') {
          const degree = graph.degree(nodeId);
          if (degree < filters.minSize) infraToRemove.push(nodeId);
        }
      });
      for (const nodeId of infraToRemove) {
        // Remove connected orphan domains first
        const neighbors = graph.neighbors(nodeId);
        graph.dropNode(nodeId);
        for (const n of neighbors) {
          if (graph.hasNode(n) && graph.degree(n) === 0) graph.dropNode(n);
        }
      }
    }

    return graph;
  }, [data, filters]);

  useEffect(() => {
    if (!containerRef.current) return;

    const graph = buildGraph();
    if (!graph || graph.order === 0) {
      // Clean up existing sigma instance
      if (sigmaRef.current) {
        sigmaRef.current.kill();
        sigmaRef.current = null;
      }
      return;
    }

    // Run ForceAtlas2 layout
    forceAtlas2.assign(graph, {
      iterations: 100,
      settings: {
        gravity: 1,
        scalingRatio: 10,
        barnesHutOptimize: true,
      },
    });

    graphRef.current = graph;

    // Clean up previous
    if (sigmaRef.current) sigmaRef.current.kill();

    const sigma = new Sigma(graph, containerRef.current, {
      renderLabels: true,
      labelRenderedSizeThreshold: 8,
      defaultEdgeColor: '#374151',
      defaultNodeColor: '#94a3b8',
    });

    // Click handler
    sigma.on('clickNode', ({ node }) => {
      const attrs = graph.getNodeAttributes(node);
      if (attrs.type === 'domain') {
        onClickNode?.({ type: 'domain', id: node, label: attrs.label });
      } else {
        // Highlight connected domains
        const neighbors = graph.neighbors(node);
        const domainNeighbors = neighbors.filter(n =>
          graph.hasNode(n) && graph.getNodeAttributes(n).type === 'domain'
        );
        onClickNode?.({
          type: attrs.type,
          id: node,
          label: attrs.label,
          domains: domainNeighbors.map(n => graph.getNodeAttributes(n).label),
        });

        // Visual highlight
        graph.forEachNode((n, a) => {
          if (n === node || domainNeighbors.includes(n)) {
            graph.setNodeAttribute(n, 'highlighted', true);
            graph.setNodeAttribute(n, 'color',
              a.type === 'domain' ? '#fbbf24' : TYPE_COLORS[a.type]);
          } else {
            graph.setNodeAttribute(n, 'color', '#1f2937');
          }
        });
        sigma.refresh();
      }
    });

    // Click on stage to reset
    sigma.on('clickStage', () => {
      graph.forEachNode((n, a) => {
        graph.setNodeAttribute(n, 'color', TYPE_COLORS[a.type] || '#94a3b8');
      });
      sigma.refresh();
      onClickNode?.(null);
    });

    sigmaRef.current = sigma;

    return () => {
      sigma.kill();
      sigmaRef.current = null;
    };
  }, [buildGraph, onClickNode]);

  return <div ref={containerRef} className="h-full w-full" />;
}
```

**Step 2: Implement `ClusterView.jsx`**

```jsx
import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useData } from '@/context/DataContext';
import SigmaGraph from '@/components/SigmaGraph';

const INFRA_TYPES = [
  { key: 'mx_host', label: 'MX Host', color: '#3b82f6' },
  { key: 'ip', label: 'IP Address', color: '#f97316' },
  { key: 'registrar_ns', label: 'Registrar+NS', color: '#22c55e' },
];

export default function ClusterView() {
  const { clusters } = useData();
  const navigate = useNavigate();
  const [selectedNode, setSelectedNode] = useState(null);
  const [typeFilters, setTypeFilters] = useState(['mx_host', 'ip', 'registrar_ns']);
  const [minSize, setMinSize] = useState(3);

  const handleToggleType = (type) => {
    setTypeFilters(prev =>
      prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
    );
  };

  const handleClickNode = useCallback((node) => {
    if (node?.type === 'domain') {
      navigate(`/investigate/${node.label}`);
    } else {
      setSelectedNode(node);
    }
  }, [navigate]);

  const nodeCount = clusters?.nodes?.length || 0;
  const edgeCount = clusters?.edges?.length || 0;

  return (
    <div className="flex h-[calc(100vh-8rem)] gap-4">
      {/* Main graph area */}
      <div className="relative flex-1 rounded-lg border border-border-subtle bg-gray-900">
        {/* Controls overlay */}
        <div className="absolute top-4 left-4 z-10 space-y-3 rounded-lg bg-surface-raised/90 p-4 backdrop-blur">
          <div>
            <div className="mb-2 text-xs font-semibold uppercase text-gray-500">Node Types</div>
            {INFRA_TYPES.map(({ key, label, color }) => (
              <label key={key} className="flex items-center gap-2 py-0.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={typeFilters.includes(key)}
                  onChange={() => handleToggleType(key)}
                  className="rounded"
                />
                <span className="h-3 w-3 rounded-full" style={{ backgroundColor: color }} />
                <span className="text-xs text-gray-300">{label}</span>
              </label>
            ))}
          </div>
          <div>
            <div className="mb-1 text-xs font-semibold uppercase text-gray-500">
              Min Cluster Size: {minSize}
            </div>
            <input
              type="range"
              min={3}
              max={20}
              value={minSize}
              onChange={e => setMinSize(parseInt(e.target.value))}
              className="w-full"
            />
          </div>
          <div className="text-xs text-gray-500">
            {nodeCount} nodes / {edgeCount} edges
          </div>
        </div>

        <SigmaGraph
          data={clusters}
          filters={{ types: typeFilters, minSize }}
          onClickNode={handleClickNode}
        />
      </div>

      {/* Detail sidebar */}
      {selectedNode && selectedNode.domains && (
        <div className="w-80 overflow-y-auto rounded-lg border border-border-subtle bg-surface-raised p-4">
          <div className="mb-3">
            <div className="text-xs font-semibold uppercase text-gray-500">{selectedNode.type}</div>
            <div className="font-mono text-sm text-gray-200 break-all">{selectedNode.label}</div>
          </div>
          <div className="text-xs text-gray-500 mb-2">
            {selectedNode.domains.length} connected domains
          </div>
          <div className="space-y-1">
            {selectedNode.domains.map(domain => (
              <button
                key={domain}
                onClick={() => navigate(`/investigate/${domain}`)}
                className="block w-full rounded px-2 py-1 text-left text-sm font-mono text-blue-400 hover:bg-gray-700"
              >
                {domain}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
```

**Step 3: Verify build**

Run: `cd frontend && npm run build`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add frontend/src/pages/ClusterView.jsx frontend/src/components/SigmaGraph.jsx
git commit -m "feat: add cluster visualization with Sigma.js network graph"
```

---

## Task 6: CI Integration

**Files:**
- Modify: `.github/workflows/update_intelligence.yml` (lines 244-374)

**Step 1: Update the CI workflow**

In `update_intelligence.yml`, make these changes:

**a)** After the "Infrastructure Fingerprinting" step (line 245), replace the "Build Investigate Index" step (lines 247-249) with:

```yaml
      - name: Build Frontend Data
        run: python scripts/build_frontend_data.py
```

**b)** In the "Generate Pivots & Stats" step (lines 346-351), remove the `build_dashboard_data.py` call. Change:
```yaml
      - name: Generate Pivots & Stats
        run: |
          python scripts/generate_pivots.py --input data/dea_domains_probed.csv
          python scripts/track_history.py
          python scripts/build_dashboard_data.py
```
To:
```yaml
      - name: Generate Pivots & Stats
        run: |
          python scripts/generate_pivots.py --input data/dea_domains_probed.csv
          python scripts/track_history.py
```

**c)** In the "Build Dashboard Frontend" step (lines 366-375), simplify to:
```yaml
      - name: Build Dashboard Frontend
        timeout-minutes: 5
        run: |
          cd frontend
          npm ci
          npm run build
```

The Vite config now builds directly to `docs/` with `emptyOutDir: false`, so no need for the `docs_new` copy dance.

**Step 2: Verify workflow YAML is valid**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/update_intelligence.yml'))" && echo "YAML valid"`
Expected: "YAML valid"

**Step 3: Commit**

```bash
git add .github/workflows/update_intelligence.yml
git commit -m "ci: integrate build_frontend_data.py and update frontend build step"
```

---

## Summary of Deliverables

| Task | Deliverable | Tests |
|------|-------------|-------|
| 1 | `scripts/build_frontend_data.py` | `tests/test_build_frontend_data.py` (10 tests) |
| 2 | React scaffold (Layout, DataContext, routing) | Manual: `npm run build` succeeds |
| 3 | `/investigate/:domain` detail view | Manual: navigate to domain |
| 4 | `/matches` dashboard with table | Manual: sort, filter, paginate |
| 5 | `/clusters` Sigma.js graph | Manual: filter, click, zoom |
| 6 | CI workflow update | YAML validation |
