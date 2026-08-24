# VPN IP Intelligence Pipeline — Operational Guide

## Overview

- **20 active VPN providers**, automated daily collection
- **Daily Data Update** workflow runs at **07:00 UTC**
- `vpn_ip_intel.py` called with default args in the finalize stage

---

## Fully Automated Providers (Zero Maintenance)

These providers pull fresh data every CI run with no manual intervention:

| Provider | Collection Method |
|----------|------------------|
| Mullvad | Public API |
| NordVPN | Public API |
| PIA | Public API |
| Surfshark | Public API + DNS |
| CyberGhost | DNS enum |
| TorGuard | DNS enum |
| Windscribe | DNS enum |
| VPNGate | Public CSV API |
| FastVPN | Config ZIP |
| TunnelBear | Config ZIP |
| AirVPN | JSON API |
| VyprVPN | DNS enum |
| FlowVPN | DNS enum |
| Njalla | DNS enum |
| Hotspot Shield | DNS + Shodan |
| Urban VPN | Shodan |
| PrivadoVPN | Config ZIP |

**ExpressVPN** also auto-fetches from the gluetun GitHub repo (~390 IPs), but the local cache adds ~1,000 more IPs. See the quarterly refresh section below.

---

## Quarterly Manual Refreshes

### ExpressVPN Local Cache

The cache file is **gitignored** (`.gitignore` excludes `data/vpn_seeds/expressvpn_data.json`), so refreshing it does **not** produce a commit. Its extra IPs reach the repo only when the pipeline is next run locally and the regenerated `data/vpn_relay_ips.csv` is committed. Reading the source requires an **elevated** shell.

```powershell
# Run in elevated PowerShell
Copy-Item "C:\Program Files\ExpressVPN\data\data.json" "data\vpn_seeds\expressvpn_data.json"
```

### ProtonVPN Cache

The client stores servers as `Servers.<hash>.bin`, where the hash changes between client versions — glob for it rather than hard-coding the name. Unlike ExpressVPN, this seed **is** tracked and committed.

```powershell
$src = Get-ChildItem "$env:LOCALAPPDATA\Proton\Proton VPN\Storage\Servers.*.bin" | Select-Object -First 1
Copy-Item $src.FullName "data\vpn_seeds\protonvpn\Servers.current.bin"
git add data/vpn_seeds/protonvpn/ && git commit -m "data: refresh ProtonVPN cache" && git push
```

### Mullvad Exit Probe

Requires an active Mullvad WireGuard connection — the SOCKS5 relays are only
reachable from inside the tunnel.

```bash
python scripts/mullvad_exit_probe.py
git add data/vpn_seeds/mullvad_exit_ips.csv && git commit -m "data: refresh Mullvad exit IPs" && git push
```

**Last refreshed: 2026-08-24** — 526 → **550 relays**, 550 unique exit IPs,
matching every currently active relay with SOCKS5.

Worth knowing before trusting the output: the script **overwrites** the seed
wholesale at the end of a run, so a tunnel drop mid-probe silently shrinks the
file. Probe to a temporary path and reconcile against the previous seed before
replacing it. In the last refresh, 545/550 probed clean, 3 recovered on retry,
and 2 (`fi-hel-wg-001`, `gb-lon-wg-008`) were retained at their older
`probe_date` — still active but consistently unreachable via SOCKS5. Keeping
those rows preserves known-good exit IPs and dates them honestly rather than
dropping coverage. 27 relays were dropped only after confirming against the API
that they are no longer active.

---

## Annual Refreshes

- **Astrill seed**: obtain from Spur Intelligence, save to `data/vpn_seeds/spur_astrill_YYYY.txt`
- The script warns when the seed file exceeds **180 days old**

> [!IMPORTANT]
> The current seed is `spur_astrill_2024.txt` — roughly two years old, and **no
> newer Spur seed is available**. Astrill is the highest-weighted indicator in
> `vpn_provider_scores.csv` (25 pre-hire / 30 post-hire), so the strongest
> signal in the pipeline rests on the oldest data.
>
> Shodan org discovery partly compensates: see below.

---

## Shodan Org Discovery

Four providers discover IPs beyond their seed lists via Shodan organisation
search: **Astrill, Urban VPN, ExpressVPN, Hotspot Shield**.

This path produced **nothing at all** until 2026-08-24. Every committed dataset
had zero rows with a `shodan` source. Two causes, both silent:

1. The search shelled out to the `shodan` CLI, which authenticates from
   `~/.shodan/api_key` written by `shodan init` — it does **not** read the
   environment. The workflow step running `vpn_ip_intel.py` set no
   `SHODAN_API_KEY` at all, so no key existed in any form.
2. Only `FileNotFoundError` and `TimeoutExpired` were caught. An
   unauthenticated CLI exits non-zero with empty stdout, which the parser read
   as "no results" — a dead credential was indistinguishable from a genuine
   empty answer. The step is `continue-on-error`, so nothing surfaced.

It now uses the Python API, which reads `SHODAN_API_KEY` from the environment,
and pages with `search_cursor`. Failure modes are distinguishable: a missing key
logs at ERROR naming the consequence, an empty result warns that the org name
may be stale, and exceptions degrade to the seed rather than crashing.

**The `Infrastructure Intel (ASN/VPN/Tor)` workflow step must pass
`SHODAN_API_KEY`.** Without it these four providers fall back to seed lists
only — which for Astrill means 2024 data.

First results after the fix:

| Provider | IPs discovered |
|---|---|
| ExpressVPN | 360 |
| Hotspot Shield | 16 |
| Astrill | 4 |

Urban VPN returns **0**, which now emits a warning — the configured org string
(`Urban VPN`) is likely wrong. Left visible rather than guessed at.

### Checking it still works

```bash
# Should be non-zero. Zero means discovery has silently broken again.
python -c "
import csv, io, collections
c = collections.Counter()
for r in csv.DictReader(io.open('data/vpn_relay_ips.csv', encoding='utf-8', newline='')):
    if 'shodan' in (r.get('source') or ''):
        c[r['provider']] += 1
print(sum(c.values()), dict(c))
"
```

---

## Weekly Health Check (5 minutes)

```bash
# Check last 3 workflow runs
gh run list --workflow=update_intelligence.yml --limit 3

# Check VPN IP counts in latest run
gh run view $(gh run list --workflow=update_intelligence.yml --limit 1 --json databaseId -q '.[0].databaseId') --log 2>&1 | grep -E "(VPN relay|RDAP egress|exit seeds|active ingress|active relays)"
```

---

## Output Files

| File | Contents | Updated |
|------|----------|---------|
| `data/vpn_relay_ips.csv` | Master sheet (all IPs + prefix-inferred + egress-inferred) | Daily (auto) |
| `data/vpn_relay_lookup.csv` | Lean 13-col LogScale lookup — all rows (exact-IP + CIDR + inactive), <10 MB | Daily (auto) |
| `data/vpn_relay_lookup.json` | Same 13 cols as a compact JSON array, **active rows only** (~8 MB), for CrowdStrike Fusion SOAR HTTP-action pulls (JSONPath-parseable). Un-ignored in `.gitignore` so CI commits it. | Daily (auto) |
| `data/vpn_exit_ips.csv` | Legacy compat (IP rows only, no prefix rows) | Daily (auto) |
| `data/vpn_exit_ips/{provider}.csv` | Per-provider breakdowns | Daily (auto) |
| `data/vpn_provider_scores.csv` | Risk scoring tiers | Manual (when providers change) |

---

## DPRK Threat Scoring

| Provider | Pre-hire Score | Post-hire Score | Tier | Evidence |
|----------|---------------|----------------|------|----------|
| Astrill | 25 | 30 | anchor | Mandiant, Microsoft, Spur, Unit42, SecurityScorecard |
| Mullvad | 20 | 25 | anchor | Kudelski: 2nd most-used by DPRK IT workers, after Astrill |
| ExpressVPN | 15 | 25 | anchor | Mandiant: RGB ORB tunnels |
| NordVPN | 15 | 25 | anchor | Mandiant: UNC4899 JumpCloud |
| TorGuard | 15 | 25 | anchor | Mandiant: UNC4899 JumpCloud |
| Hotspot Shield | 12 | 20 | strong | Recorded Future: 63% NK usage |

---

## Disabled Providers (and Why)

- **IPVanish**: Config ZIP returns 403 from CI runners (Cloudflare bot protection)
- **HMA/HideMyAss**: Config download URL redirects to dead host `vpn.hidemyass.com`
- **Hola VPN**: API returns 403 — blocks all non-browser-extension requests

---

## Troubleshooting

- **Provider returns 0 IPs** — API endpoint changed or is down; check the provider's URL manually
- **DNS enum returns fewer IPs than expected** — some hostnames may have been decommissioned; this is normal
- **RDAP expansion shows 0 blocks** — RDAP rate limiting; the script has built-in 0.3s delays
