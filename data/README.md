# 📂 Data Dictionary

This directory contains the automated intelligence outputs of the pipeline. All files are updated daily by GitHub Actions.

## 🚨 Primary Intelligence Lists

These are the core datasets for ingestion into security tools (SIEM/SOAR/Firewalls).

| File | Description | Use Case |
| :--- | :--- | :--- |
| **`dea_domains.csv`** | **Strict** list of Disposable Email Address (DEA) providers. | Block user registrations from these domains to prevent fraud/spam. |
| **`dea_domains_probed.csv`** | **Enriched** dataset containing HTTP/S fingerprint data (Title, Server, Status Code) for probed domains. | Pivot on `http_title` to find phishing kits (e.g., "Login - Wells Fargo" on a non-bank domain). |
| **`potential_typosquats.csv`** | **Proactive** list of potential lookalike domains generated via `dnstwist` for high-value targets (Banks, Crypto, Tech). | Monitor for registration of these domains to detect brand impersonation early. |
| **`discovered_ads.csv`** | Malicious domains found targeting keywords (like "download wallet") in Search Ads. | Block these domains immediately; they are actively distributing malware/scams via Ads. |
| **`ai_typosquats.csv`** | AI-detected semantic typosquats (e.g., "secure-update-apple.com") that regex might miss. | High-fidelity blocklist for brand protection. |

## 📊 Analytics & Metrics

Derived statistics useful for trend analysis and dashboarding.

| File | Description | Schema |
| :--- | :--- | :--- |
| **`mx_counts.csv`** | Top Mail Exchange (MX) providers used by disposable domains. | `mx_host, domain_count, primary_asn` |
| **`asn_counts.csv`** | Top Hosting Providers (ASNs) hosting disposable/abuse domains. | `asn, asn_name, domain_count` |
| **`risk_counts.csv`** | Counts of domains flagged with specific risk tags (e.g., "HighRisk:Nicenic"). | `risk_tag, count` |
| **`web_server_counts.csv`** | Top HTTP Server headers (e.g., nginx, cloudflare) found during probing. | `server, count` |
| **`visual_clusters.json`** | Groups of domains that look visually identical (based on pHash). | JSON Object (Array of Clusters) |

## 🧠 Infrastructure Intelligence

Contextual data on the "backend" of the internet.

| File | Description |
| :--- | :--- |
| **`risky_asn_list.csv`** | ASNs that host a disproportionately high number of abuse domains. |
| **`suspicious_asns.csv`** | Aggregated list of ASNs known for Bulletproof hosting or Botnet activity. |
| **`tor_nodes.csv`** | Active Tor Exit Nodes enriched with ASN data. |
| **`vpn_asns.csv`** | ASNs belonging to commercial VPN/VPS providers (often used to mask attacker origin). |

## 📥 Configuration & Inputs

Files that control the scope of the intelligence gathering.

* **`targets.txt`**: The "Seed List" of high-value brands (Banks, Crypto, SaaS) used to generate typosquats. **Edit this file to expand monitor coverage.**
* **`dea_allowlist.csv`**: Domains that are *not* DEA but might be flagged (false positive prevention).

---
*Data is generated automatically. Do not manually edit CSVs unless adding to `targets.txt` or `dea_allowlist.csv`.*
