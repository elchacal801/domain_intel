# Remote Access & IP-KVM Detection

Detection of internet-exposed IP-KVM hardware and remote-management (RMM) tooling, the infrastructure pattern behind DPRK IT-worker laptop farms.

## Why this exists

2026 reporting (Google Cloud Threat Intelligence, Nisos, runZero) describes laptop farms built on **IP-KVM hardware**: a US-based facilitator receives and racks company laptops while the actual worker, in DPRK or China, drives them remotely over KVM. Where KVM hardware is unavailable, **RMM tooling** — AnyDesk, TeamViewer, RustDesk, ScreenConnect, Chrome Remote Desktop — serves as the fallback layer.

An IP-KVM is a hardware dongle on the laptop's USB and HDMI. It presents as keyboard, video and mouse, so **no software runs on the host and EDR sees nothing**. Geolocation, device posture and network checks all pass, because the laptop genuinely is sitting in the US.

MITRE covers the technique as **T1219.003 (Remote Access Hardware)**, with detection strategy **DET0159** naming TinyPilot and PiKVM. DET0159 is host-based — USB enumeration, EDID announcements, mount paths — which an external pipeline cannot observe. This module provides the complementary **network-side** view.

Google Cloud notes these connections originate predominantly from **Astrill VPN** addresses, a population this pipeline already resolves — see [VPN IP Intelligence](vpn-ip-intel-operations.md).

---

## Components

| Component | Role |
|---|---|
| `scripts/enrich_rmm_exposure.py` | Classifies known IPs — is this host exposing KVM/RMM? |
| `scripts/hunt_kvm.py` | Discovers unknown IP-KVM devices proactively via Shodan |
| `config/fingerprints/FP-0011-remote-access-exposure.yaml` | Scores findings on domain rows |
| `data/kvm_hardware_identifiers.csv` | Host-side artifacts for the EDR/LogScale side |
| `data/vpn_seeds/kvm_silentpush_20260824.csv` | 1,878-IP baseline from Silent Push |

The two scripts answer different questions. **Classification** takes IPs you already have and asks what they expose; **discovery** finds hosts you did not know about. Discovery keeps its own baseline (`data/known_kvm_ips.txt` and the Silent Push seed) rather than writing into `known_campaign_ips.txt`, so KVM findings never blur disposable-email campaign attribution.

---

## Signatures

### IP-KVM — HTTP titles and favicon hashes

Favicon hashes matter because a title is trivially customised while the stock favicon usually survives a rebrand. Source: runZero's IP-KVM survey.

| Product | Titles | Favicon hashes |
|---|---|---|
| PiKVM | `pikvm`, `pi-kvm` | `-1040945478`, `-692926325` |
| TinyPilot | `tinypilot` | `-996415781` |
| JetKVM | `jetkvm` | `-1261329937` |
| GLKVM | `glkvm` | `-186012304` |
| NanoKVM | `nanokvm` | `1323732765` |
| BliKVM | `blikvm` | — |
| Apache Guacamole | `apache guacamole`, `guacamole` | — |

### RMM — ports and product banners

| Product | Ports | Banner / title |
|---|---|---|
| RustDesk | 21115, 21116, 21117 | `rustdesk` |
| AnyDesk | 7070 | `anydesk` |
| TeamViewer | 5938 | `teamviewer` |
| ScreenConnect | 8172 | `screenconnect`, `connectwise` |
| MeshCentral | — | `meshcentral` |
| VNC | 5900–5905 | `vnc`, `realvnc`, `tightvnc` |
| RDP | 3389 | `remote desktop`, `ms-wbt-server` |

MeshCentral was found by passive DNS: a host serving `mesh.<domain>` beside `rust.<domain>`. It has no fixed port worth matching, so it is identified by title and banner only.

---

## Scoring — rarity drives confidence

FP-0011 matches the `kvm_detected` / `rmm_detected` columns written onto domain rows, the same way FP-0010 consumes `proxy_detected` from `enrich_proxy_check.py`.

| Signal | Δ | Reasoning |
|---|---|---|
| PiKVM, TinyPilot, JetKVM, NanoKVM, GLKVM, BliKVM | **+30** | dedicated KVM hardware on the public internet is genuinely unusual |
| Astrill egress | **+25** | remote access *reachable from a VPN egress* is the reported pattern |
| RustDesk, AnyDesk, TeamViewer, ScreenConnect | +20 | named in reporting, but also ordinary IT tooling |
| Apache Guacamole | +15 | legitimate enterprise gateway as well |
| Mullvad egress / proxy detected | +10 | corroboration |
| **RDP** | **−25** | ubiquitous — must never carry a match alone |
| **VNC** | **−20** | ubiquitous |

Base confidence 40. The negative modifiers are the important design decision: without them, port 3389 alone would flood the output. In the first production run, 2 of 3 findings were plain RDP.

---

## Running it

### Classification

```bash
python scripts/enrich_rmm_exposure.py \
  --ip-list data/known_campaign_ips.txt \
  --source data/dea_domains_probed.csv:a_record \
  --source data/vpn_relay_ips.csv:ip \
  --asn-seed data/kadnap_operator_asns.csv \
  --output data/rmm_exposure.csv \
  --annotate data/dea_domains_probed.csv \
  --budget 1000
```

`--source PATH[:COLUMN]` is repeatable; the column defaults to `a_record`.

**The output file is the progress ledger, not the cache.** Results are read back, merged by IP with the newest record winning, and rewritten. `--recheck-days` (default 30) skips recently-checked IPs. Progress therefore survives cache expiry or loss — anchoring it to the 30-day SQLite cache would silently restart the sweep on day 31.

Runs are checkpointed every `--checkpoint-every` lookups (default 100), so an interrupted run loses nothing and the next invocation resumes where it stopped.

### Discovery

```bash
python scripts/hunt_kvm.py --budget 20
python scripts/hunt_kvm.py --dry-run     # print queries, call nothing
```

New hosts are appended to `data/kvm_hunt_history.csv` and surfaced as GitHub Actions `::warning::` annotations. **The script always exits 0** — the discovery job has no `continue-on-error`, so a non-zero exit on findings would fail the job and abort the pipeline.

---

## Cost and rate limits

Measured on a Shodan **Basic** plan: 145 host lookups plus 15 searches consumed **99 query credits**, all attributable to the searches.

> `api.host()` does not bill query credits. Searches do.

The binding constraint for classification is therefore wall clock at roughly **1 request/second**, not budget. The combined domain and VPN relay sets hold ~90,500 unique IPs, about 26 hours serially — hence the bounded per-run slice, the request throttle, and retry with exponential backoff. A genuine `No information available` is treated as an answer, not a failure, so it does not consume retries.

---

## Query syntax facts worth knowing

Each of these was found by testing, and each fails **silently** if got wrong.

- **Shodan supports neither boolean `OR` nor parentheses.** An early ASN sweep returned `APIError: The search query was invalid` for all five operator ASNs.
- **Comma-separated values OR correctly inside `http.title`** — but **not** inside `http.html` or `http.favicon.hash`. A collapsed `http.html:"a","b"` returns **zero results**, silently disabling the query. Body and favicon terms each need their own query.
- **`http.html` consistently outperforms `http.title`.** A site can rename its `<title>`; the body still carries the words users read.

---

## Discovery query performance

Measured against live Shodan, 2026-08-24:

```
1397  http.title:"pikvm","pi-kvm","tinypilot","jetkvm","nanokvm","glkvm","blikvm"
 664  http.html:"pikvm"
 560  ssl:"PiKVM"
 479  http.favicon.hash:-1040945478
 431  http.html:"nanokvm"
 338  http.html:"pikvm" -port:443 -port:80      <- roughly half are off 443/80
 100  http.html:"jetkvm"
  97  http.html:"guacamole" http.title:"Guacamole"
  70  http.html:"tinypilot"
```

### Rejected after measuring

| Candidate | Volume | Why not |
|---|---|---|
| `ssl.jarm:27d28d28d000…` | 10,439 | A TLS-stack fingerprint shared with ordinary nginx, not a device signature. A test forbids using it unqualified. |
| `ssl.cert.issuer.CN:"PiKVM"` | 7 | Shodan does not index the certificate organisation, despite 7,531 of 10,000 Silent Push records carrying issuer `O=PiKVM`. |
| `http.html:"guacamole"` bare | 12,780 | Against just 5 for `http.title:"Apache Guacamole"`. Requiring both narrows to 97, which is reviewable. |
| Favicon clustering of scanned hosts | — | Of 2,006 hosts, only 9 favicons sat on mail-related titles, and the high-volume ones are generic defaults shared by 1,087,526 and 34,334 hosts. Effective for IP-KVM; not discriminating for DEA. |

---

## Coverage caveat

**Shodan surfaces roughly 600 PiKVM hosts where Silent Push observes 14,000+.**

Shodan is a supplementary channel here, not the primary one. The Silent Push export seeds the baseline so the hunt reports genuinely new hosts rather than re-reporting that population. If IP-KVM visibility matters to an investigation, query a web-crawling source directly rather than relying on this hunt alone.

---

## Interpreting findings

**A hit inside a large shared-hosting ASN is a lead, not an attribution.** A worked example: an Apache Guacamole instance in AS29802 (Hivelocity) initially looked like a finding in a KadNap-attributed ASN. Passive DNS resolved it — the host served `mesh`, `rust`, `search`, `mail`, `cloud`, `meet`, `chat`, `baserow`, `containers` and `workflow` under one domain. That is a self-hosted homelab, not laptop-farm infrastructure.

Two lessons carried into the design: ASN-wide sweeps of large commercial hosts mostly surface other people's side projects, and corroborating signals are weighted above raw detection for exactly this reason.

---

## Host-side identifiers

`data/kvm_hardware_identifiers.csv` records artifacts this pipeline **cannot** query but the EDR and LogScale side can — USB vendor/product IDs, default serials (`CAFEBABE` for PiKVM, `6b65796d696d6570690` for TinyPilot), eight Raspberry Pi MAC OUIs, and `/dev/hidg0`, the write target used by the Scapy ARP-listener C2 documented in laptop-farm reporting.

Every row cites its source.

---

## Related

- [VPN IP Intelligence Operations](vpn-ip-intel-operations.md) — Astrill and Mullvad egress resolution, which supplies FP-0011's strongest corroborating signal
- [Detection Logic](detection_logic.md) — vendor-agnostic SOC detection patterns
