# Investigation: DEA Infrastructure Networks (Clusters 1-3)

**Date:** 2026-02-17
**Subject:** Multi-cluster DEA Infrastructure (`51.254.35.55`, `193.108.118.7`, `47.88.24.103`)
**Related Files:** `investigation_51.254.35.55.md`, `pivot_otx_results.csv`

## Executive Summary

This investigation expands upon the initial findings of Cluster 1 (`51.254.35.55`) to include two additional infrastructure clusters identified in intelligence briefs. These clusters support a large-scale Synthetic Identity and App Fraud operation.

## Cluster Analysis

### Cluster 1: OVH VPS (`51.254.35.55`)

* **Role:** Primary "Public Email Service" hosting.
* **Status:** High volume, actively tracked in `manual_candidates.csv`.
* **Key Indicator:** `SilentPush` feeds.

### Cluster 2: GTHost (`193.108.118.7`)

* **Role:** Specialized DEA & Monetization.
* **Key Domains:** `mx.fex.plus`, `fex.plus`, `any.pink`.
* **Automated Pivot (OTX) Findings:**
  * **Crypto/Finance:** `btc.glass`, `seed.bitcoin.sipa.be`, `bridgecredit.org`.
  * **Infrastructure:** `fastdisk.io`, `imglist.io`.
  * **Volume:** 73 associated domains found via Passive DNS.
* **Threat Path Mapping:** Phase 5 (Monetization), specifically crypto conversion and credit bust-out prep.

### Cluster 3: Alibaba Cloud (`47.88.24.103`)

* **Role:** Mobile App Distribution & DEA.
* **Key Domains:** `temp-mail-pro.com`, `mx1.tempmail.so`.
* **Automated Pivot (OTX) Findings:**
  * **App Distribution:** `deploygate.io`, `diawi.io`, `appdropx.com`.
  * **Significance:** These platforms are frequently used to side-load malicious apps (loaders, spyware) bypassing official stores (TP-0012).
* **Volume:** 9 associated domains.

## Recommendations

1. **Block**: All identified IPs and domains (`dea_domains.csv`).
2. **Monitor**: `bridgecredit.org` and `diawi.io` links for specific fraud campaigns.
3. **Hunt**: Continue using `pivot_otx.py` for passive DNS monitoring of these IPs.
