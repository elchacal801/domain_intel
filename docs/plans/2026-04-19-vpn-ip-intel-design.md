# VPN Exit IP Intelligence Collection — Design Spec

**Date:** 2026-04-19
**Status:** Draft

## Problem

domain_intel's existing VPN detection operates at ASN granularity (`vpn_intel.py` fetches VPN/VPS ASN lists from NullifiedCode). This catches domains hosted on VPN-associated ASNs but cannot attribute traffic to specific VPN providers. For DPRK IT worker detection and fraud infrastructure analysis, we need IP-level attribution: "this domain's A-record resolves to a known Mullvad exit node" or "this IP is a confirmed Astrill exit."

## Goals

1. Collect VPN exit node IPs from major commercial providers at IP granularity
2. Publish per-provider and combined IP lists as standalone data products in `data/`
3. Enrich `dea_domains_probed.csv` with provider-specific `risk_tags` (e.g., `VPN:Mullvad`, `VPN:Astrill`)
4. Run daily as part of the existing `update_intelligence.yml` GitHub Actions pipeline
5. Zero Shodan credit cost (use only free APIs and queries)

## Non-Goals

- Residential proxy detection (different infrastructure, different methods)
- VPN protocol fingerprinting (we care about "is this IP a VPN exit?" not "what protocol?")
- Real-time detection (batch pipeline, daily refresh is sufficient)

## Architecture

### Provider Plugin System

A single script `scripts/vpn_ip_intel.py` with a provider registry. Each provider is a Python class implementing a common interface.

```python
class BaseProvider:
    """Abstract base for VPN IP providers."""
    name: str           # e.g., "mullvad"
    display_name: str   # e.g., "Mullvad VPN"

    def fetch(self) -> list[dict]:
        """Returns list of VPNNode dicts."""
        raise NotImplementedError
```

Each `fetch()` returns a list of dicts with the unified schema (see Data Model below). The orchestrator calls all registered providers, merges results, enriches with Team Cymru ASN data, and writes output CSVs.

### Provider Implementations

| Provider | Method | Refresh | Confidence | Notes |
|----------|--------|---------|------------|-------|
| **Mullvad** | Public API (`api.mullvad.net/www/relays/all/`) | Daily | `confirmed` | Authoritative. Returns hostname, IP, type, location, provider, owned status. 578 servers, ~593 IPs. |
| **Astrill** | Spur 2024 seed list + RDAP block validation + Shodan `org:"Astrill Systems Corp"` free search | Daily (Shodan), monthly (RDAP) | `confirmed` (RDAP blocks) / `medium` (Spur-only) | ~1,193 confirmed, ~1,210 ambiguous, ~6 Shodan-only. Spur seed committed to repo. |
| **NordVPN** | Public recommendations API (`api.nordvpn.com/v1/servers?limit=99999`) | Daily | `confirmed` | Returns full server list with IPs, locations, technologies (WireGuard/OpenVPN/obfuscated). ~6,000+ servers. |
| **ProtonVPN** | Public API (`api.protonvpn.ch/vpn/logicals`) | Daily | `confirmed` | Used by open-source client. Returns server IPs, locations, features (Secure Core, P2P, Tor). ~3,000+ servers. |
| **Surfshark** | Client API (endpoint to be validated during implementation — their app fetches a server list at startup) | Daily | `confirmed` | Server list used by client app. ~3,200+ servers. Exact API URL needs traffic capture or reverse-engineering of their open-source tools. If unavailable, stub like ExpressVPN. |
| **ExpressVPN** | Static list + community feeds | Monthly | `low` | No public API. Most opaque provider. Lower priority, add when a reliable source is identified. Stub initially. |

### Data Model

Unified schema for `data/vpn_exit_ips.csv`:

| Column | Type | Description |
|--------|------|-------------|
| `ip` | str | IPv4 address |
| `provider` | str | Lowercase provider name: `mullvad`, `astrill`, `nordvpn`, `protonvpn`, `surfshark` |
| `confidence` | str | `confirmed`, `high`, `medium`, `low` |
| `country` | str | 2-letter country code (from provider API or Team Cymru) |
| `city` | str | City name (from provider API, blank if unavailable) |
| `server_type` | str | `wireguard`, `openvpn`, `bridge`, `exit`, `unknown` |
| `asn` | str | ASN from Team Cymru (e.g., `AS9009`) |
| `asn_name` | str | ASN organization name |
| `source` | str | Data source: `mullvad_api`, `spur_2024+rdap`, `shodan_org`, `nordvpn_api`, etc. |
| `source_date` | str | ISO date of last collection |
| `hostname` | str | Server hostname if available (e.g., `se-got-wg-001`) |

### Output Files

```
data/
  vpn_exit_ips.csv              # Combined, all providers (~10K+ IPs)
  vpn_exit_ips/
    mullvad.csv                 # Per-provider
    astrill.csv
    nordvpn.csv
    protonvpn.csv
    surfshark.csv
  vpn_seeds/
    spur_astrill_2024.txt       # Static seed list (committed)
```

Per-provider CSVs use the same unified schema. The combined CSV is a simple concatenation with deduplication on `(ip, provider)`.

### Enrichment Integration

Two integration points with the existing pipeline:

**1. Collection step** (new, runs in finalization job):

```yaml
# In update_intelligence.yml, after existing vpn_intel.py step
- name: Collect VPN Exit IPs
  run: python scripts/vpn_ip_intel.py --output data/vpn_exit_ips.csv --output-dir data/vpn_exit_ips/
  continue-on-error: true
```

**2. Risk tagging** (modify `enrich_infrastructure.py`):

After resolving A-record IPs to ASNs, cross-reference against `vpn_exit_ips.csv`:

```python
# Load VPN IP lookup at startup
vpn_lookup = {}  # ip -> {"provider": "mullvad", "confidence": "confirmed"}
with open("data/vpn_exit_ips.csv") as f:
    for row in csv.DictReader(f):
        vpn_lookup[row["ip"]] = row

# During enrichment, after resolving a_record:
if a_record_ip in vpn_lookup:
    vpn = vpn_lookup[a_record_ip]
    risk_tags.append(f"VPN:{vpn['provider'].title()}")
```

This adds tags like `VPN:Mullvad`, `VPN:Astrill`, `VPN:Nordvpn` to the `risk_tags` column in `dea_domains_probed.csv`.

### STIX Export

Extend `export_stix.py` to include VPN exit IPs as STIX `infrastructure` objects with `labels: ["anonymization", "vpn-exit-node"]`, similar to how it already handles VPN ASNs. Group by provider.

### Provider-Specific Implementation Notes

**MullvadProvider:**
```python
def fetch(self):
    resp = requests.get("https://api.mullvad.net/www/relays/all/")
    servers = resp.json()
    return [
        {
            "ip": s["ipv4_addr_in"],
            "provider": "mullvad",
            "confidence": "confirmed",
            "country": s["country_code"],
            "city": s["city_name"],
            "server_type": s["type"],  # wireguard, bridge
            "hostname": s["hostname"],
            "source": "mullvad_api",
        }
        for s in servers if s.get("ipv4_addr_in") and s.get("active")
    ]
```

**AstrillProvider:**
```python
def fetch(self):
    nodes = []
    # 1. Load Spur seed
    spur_ips = load_seed("data/vpn_seeds/spur_astrill_2024.txt")
    
    # 2. RDAP validation (cached, checks /24 blocks for Astrill registration)
    rdap_confirmed = self._rdap_validate(spur_ips)  # Uses RDAP API
    
    # 3. Shodan org search (free query)
    shodan_ips = self._shodan_org_search("Astrill Systems Corp")
    
    # 4. Merge + assign confidence
    for ip in spur_ips:
        confidence = "confirmed" if ip in rdap_confirmed else "medium"
        nodes.append({"ip": ip, "provider": "astrill", "confidence": confidence, ...})
    
    for ip in shodan_ips - spur_ips:
        nodes.append({"ip": ip, "provider": "astrill", "confidence": "high", ...})
    
    return nodes
```

RDAP results are cached to `data/.vpn_cache/astrill_rdap.json` with a 30-day TTL to avoid hammering RDAP servers daily.

**NordVPNProvider:**
```python
def fetch(self):
    resp = requests.get("https://api.nordvpn.com/v1/servers?limit=99999")
    servers = resp.json()
    nodes = []
    for s in servers:
        for tech in s.get("technologies", []):
            # Get the server's station IP
            ip = s.get("station")  # or parse from s["ips"]
            if ip:
                nodes.append({
                    "ip": ip,
                    "provider": "nordvpn",
                    "confidence": "confirmed",
                    "country": s.get("locations", [{}])[0].get("country", {}).get("code", ""),
                    "city": s.get("locations", [{}])[0].get("country", {}).get("city", {}).get("name", ""),
                    "server_type": tech.get("name", "unknown").lower(),
                    "hostname": s.get("hostname", ""),
                    "source": "nordvpn_api",
                })
                break  # One entry per IP, not per technology
    return nodes
```

**ProtonVPNProvider and SurfsharkProvider** follow the same pattern — fetch public API, parse server list, map to unified schema.

### Error Handling

- Each provider's `fetch()` is wrapped in try/except. A failed provider logs a warning but doesn't block others.
- The script exits successfully even if some providers fail (graceful degradation, matching `continue-on-error: true` in GHA).
- Network timeouts: 15s per API call, 3 retries with exponential backoff (using existing `shared/retry.py`).

### Caching

- RDAP results: `data/.vpn_cache/astrill_rdap.json`, 30-day TTL
- Shodan org results: no cache (free query, runs daily)
- Provider API responses: no cache (daily refresh, APIs are fast)

### Testing

- Unit tests for each provider's parsing logic (mock API responses)
- Integration test: run with `--limit 10` flag to verify end-to-end with real APIs
- Existing test patterns in `tests/` directory

## Verification

1. Run `python scripts/vpn_ip_intel.py` locally, verify output CSVs
2. Check `data/vpn_exit_ips.csv` row count (~10K+ expected across all providers)
3. Spot-check 5 random IPs per provider against known data
4. Run `enrich_infrastructure.py` on a small domain set, verify `VPN:*` risk tags appear
5. Verify GHA pipeline completes with the new step added

## File Changes

| File | Action |
|------|--------|
| `scripts/vpn_ip_intel.py` | **Create** — Main collection script with provider registry |
| `scripts/enrich_infrastructure.py` | **Modify** — Add VPN IP cross-reference for risk tagging |
| `scripts/export_stix.py` | **Modify** — Add VPN exit IP infrastructure objects |
| `.github/workflows/update_intelligence.yml` | **Modify** — Add collection step |
| `data/vpn_seeds/spur_astrill_2024.txt` | **Create** — Committed static seed list |
| `data/vpn_exit_ips/` | **Create** — Output directory (gitignored, produced by pipeline) |
| `data/README.md` | **Modify** — Document new data files |
