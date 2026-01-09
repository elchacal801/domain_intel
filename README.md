# Disposable & Abuse Domain Intelligence

This repository contains my research and tooling for analyzing disposable email address (DEA) providers and high-abuse domain infrastructure.

The goal of this project is to move beyond simple static blocklists and provide **infrastructure-level intelligence** (MX records, ASNs, and hosting patterns) to help security teams, researchers, and fraud analysts detect abuse families that rotate domains frequently.

> [!NOTE]
> This repository **updates itself automatically** every day via GitHub Actions. The data in `data/` is always current.

## � Live Dashboard

View the real-time threat intelligence visualization:
> **[👉 View Live Dashboard](https://elchacal801.github.io/domain_intel/)**

## �📂 Project Structure

* **`data/`**: The authoritative source for domain lists and derived intelligence.
  * `dea_domains.csv`: The strict list of disposable provider domains.
  * `high_abuse_domains.csv`: Domains linked to spam/abuse but not strictly disposable.
  * `dea_domains_enriched.csv`: Enriched with DNS/MX infrastructure.
  * `dea_domains_reputation.csv`: Added RBL status and Domain Age (creation date).
  * `dea_domains_probed.csv`: Active HTTP/S fingerprint data (titles, server headers).
  * `domain_intel_bundle.json`: STIX 2.1 CTI Bundle for ingestion into Threat Intelligence Platforms.
  * `mx_counts.csv`: Analysis of top Mail Exchange providers.
  * `risky_asn_list.csv`: Autonomous Systems hosting high concentrations of abuse domains.
  * `suspicious_asns.csv`: Aggregated list of suspicious ASNs (botnets, bulletproof hosting).
  * `vpn_asns.csv`: ASNs associated with VPN and VPS providers.
  * `tor_nodes.csv`: Active Tor Exit Node IPs enriched with ASN data.
  * `tor_asns.csv`: ASNs significantly associated with the Tor network.
* **`scripts/`**: The Python pipeline.
  * `asn_intel.py`: Fetches and enriches suspicious ASNs from community sources.
  * `vpn_intel.py`: Aggregates VPN/VPS provider ASNs.
  * `tor_intel.py`: Tracks Tor Exit Nodes and Tor ASNs.
  * `merge_lists_v3b.py`: Aggregates and cleans public sources.
  * `enrich_infrastructure.py`: Performs bulk DNS/ASN resolution.
  * `enrich_reputation.py`: Checks RBLs and queries RDAP for domain age.
  * `probe_web.py`: Performs active HTTP/S fingerprinting (simulating visiting the site).
  * `generate_pivots.py`: Generates the intelligence pivot datasets.
  * `export_stix.py`: Exports intelligence to STIX 2.1 JSON.
* **`docs/`**: Documentation and dashboard.
  * `detection_logic.md`: Vendor-agnostic logic for using this data in detection engineering.

## 🚀 Getting Started

### Prerequisites

* Python 3.8+
* `dnspython`
* `tqdm`

Install dependencies:

```bash
pip install -r requirements.txt
```

### Reproducing the Intelligence

1. **Enrich domains**: Resolve infrastructure for the raw domain list.

    ```bash
    python scripts/enrich_infrastructure.py
    ```

    *Note: This runs 20+ concurrent workers by default. It queries public DNS.*

2. **Generate Pivots**: Create the summary stats and risk lists.

    ```bash
    python scripts/generate_pivots.py
    ```

3. **Infrastructure Intel**: Fetch and enrich ASN, VPN, and Tor data.

    ```bash
    python scripts/asn_intel.py
    python scripts/vpn_intel.py
    python scripts/tor_intel.py
    ```

4. **Analyze**: Check `data/mx_counts.csv` to see which providers are facilitating the most disposable domains.

## 🧠 Methodology

My approach focuses on **infrastructure reuse**. Threat actors can register thousands of domains (`.xyz`, `.ga`, `.tk`) cheaply, but they often point them to a smaller set of mail servers or hosting providers.

By tracking the MX records (e.g., `mail.private-email.com`) and ASNs (e.g., `DigitalOcean`), we can detect new, unknown domains belonging to these abuse families before they appear on static blocklists.

See [docs/detection_logic.md](docs/detection_logic.md) for details on how I apply this to fraud detection.

## 📜 License

Public Domain / MIT. Use this data freely for research or commercial setups.
