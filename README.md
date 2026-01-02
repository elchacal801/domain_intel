# Disposable & Abuse Domain Intelligence

This repository contains my research and tooling for analyzing disposable email address (DEA) providers and high-abuse domain infrastructure. 

The goal of this project is to move beyond simple static blocklists and provide **infrastructure-level intelligence** (MX records, ASNs, and hosting patterns) to help security teams, researchers, and fraud analysts detect abuse families that rotate domains frequently.

> [!NOTE]
> This repository **updates itself automatically** every day via GitHub Actions. The data in `data/` is always current.

## � Live Dashboard
View the real-time threat intelligence visualization:
> **[👉 View Live Dashboard](https://elchacal801.github.io/domain_intel/)**

## �📂 Project Structure

*   **`data/`**: The authoritative source for domain lists and derived intelligence.
    *   `dea_domains.csv`: The strict list of disposable provider domains.
    *   `high_abuse_domains.csv`: Domains linked to spam/abuse but not strictly disposable.
    *   `dea_domains_enriched.csv`: The fully enriched dataset (MX, IP, ASN).
    *   `mx_counts.csv`: Analysis of top Mail Exchange providers used by these domains.
    *   `risky_asn_list.csv`: Autonomous Systems hosting high concentrations of abuse domains.
*   **`scripts/`**: The Python pipeline to reproduce my work.
    *   `merge_lists_v3b.py`: Aggregates and cleans public sources.
    *   `enrich_infrastructure.py`: Performs bulk DNS/ASN resolution.
    *   `generate_pivots.py`: Generates the intelligence pivot datasets.
*   **`docs/`**: Documentation and methodology.
    *   `detection_logic.md`: Vendor-agnostic logic for using this data in detection engineering.

## 🚀 Getting Started

### Prerequisites

*   Python 3.8+
*   `dnspython`
*   `tqdm`

Install dependencies:
```bash
pip install -r requirements.txt
```

### Reproducing the Intelligence

1.  **Enrich domains**: Resolve infrastructure for the raw domain list.
    ```bash
    python scripts/enrich_infrastructure.py
    ```
    *Note: This runs 20+ concurrent workers by default. It queries public DNS.*

2.  **Generate Pivots**: Create the summary stats and risk lists.
    ```bash
    python scripts/generate_pivots.py
    ```

3.  **Analyze**: Check `data/mx_counts.csv` to see which providers are facilitating the most disposable domains.

## 🧠 Methodology

My approach focuses on **infrastructure reuse**. Threat actors can register thousands of domains (`.xyz`, `.ga`, `.tk`) cheaply, but they often point them to a smaller set of mail servers or hosting providers.

By tracking the MX records (e.g., `mail.private-email.com`) and ASNs (e.g., `DigitalOcean`), we can detect new, unknown domains belonging to these abuse families before they appear on static blocklists.

See [docs/detection_logic.md](docs/detection_logic.md) for details on how I apply this to fraud detection.

## 📜 License

Public Domain / MIT. Use this data freely for research or commercial setups.
