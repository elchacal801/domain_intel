# VPN IP Intelligence Pipeline — Operational Guide

## Overview

- **21 active VPN providers**, automated daily collection
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
| IPVanish | Config ZIP |
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

```powershell
# Run in elevated PowerShell
Copy-Item "C:\Program Files\ExpressVPN\data\data.json" "data\vpn_seeds\expressvpn_data.json"
git add data/vpn_seeds/expressvpn_data.json && git commit -m "data: refresh ExpressVPN local cache" && git push
```

### ProtonVPN Cache

```powershell
Copy-Item "$env:LOCALAPPDATA\Proton\Proton VPN\Storage\Servers.current.bin" "data\vpn_seeds\protonvpn\Servers.current.bin"
git add data/vpn_seeds/protonvpn/ && git commit -m "data: refresh ProtonVPN cache" && git push
```

### Mullvad Exit Probe

Requires an active Mullvad WireGuard connection:

```bash
python scripts/mullvad_exit_probe.py
git add data/vpn_seeds/mullvad_exit_ips.csv && git commit -m "data: refresh Mullvad exit IPs" && git push
```

---

## Annual Refreshes

- **Astrill seed**: obtain from Spur Intelligence, save to `data/vpn_seeds/spur_astrill_YYYY.txt`
- The script warns when the seed file exceeds **180 days old**

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
| `data/vpn_exit_ips.csv` | Legacy compat (IP rows only, no prefix rows) | Daily (auto) |
| `data/vpn_exit_ips/{provider}.csv` | Per-provider breakdowns | Daily (auto) |
| `data/vpn_provider_scores.csv` | Risk scoring tiers | Manual (when providers change) |

---

## DPRK Threat Scoring

| Provider | Pre-hire Score | Post-hire Score | Tier | Evidence |
|----------|---------------|----------------|------|----------|
| Astrill | 25 | 30 | anchor | Mandiant, Microsoft, Spur, Unit42, SecurityScorecard |
| ExpressVPN | 15 | 25 | anchor | Mandiant: RGB ORB tunnels |
| NordVPN | 15 | 25 | anchor | Mandiant: UNC4899 JumpCloud |
| TorGuard | 15 | 25 | anchor | Mandiant: UNC4899 JumpCloud |
| Hotspot Shield | 12 | 20 | strong | Recorded Future: 63% NK usage |

---

## Disabled Providers (and Why)

- **HMA/HideMyAss**: Config download URL redirects to dead host `vpn.hidemyass.com`
- **Hola VPN**: API returns 403 — blocks all non-browser-extension requests

---

## Troubleshooting

- **Provider returns 0 IPs** — API endpoint changed or is down; check the provider's URL manually
- **DNS enum returns fewer IPs than expected** — some hostnames may have been decommissioned; this is normal
- **RDAP expansion shows 0 blocks** — RDAP rate limiting; the script has built-in 0.3s delays
