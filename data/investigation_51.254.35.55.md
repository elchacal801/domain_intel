# Investigation: 51.254.35.55 (SilentPush Analysis)

**Source:** SilentPush Data (`_private/1330102d-577d-4155-989d-d0d2f36b6652.csv`)
**Subject IP:** `51.254.35.55`
**ASN:** AS16276 (OVH SAS, FR)
**Date:** 2026-02-11

## Executive Summary

The analyzed data confirms that IP `51.254.35.55` hosts a massive cluster of domains associated with the "Public Email Service" campaign. The data shows a consistent pattern of high-volume domain registration and hosting on this specific OVH IP address, serving as a central infrastructure hub for this actor.

## Key Findings

1. **High Density Cluster**: The CSV contains over 7,000 entries (based on file size/lines), with a significant portion appearing to be domains hosted on or resolving to `51.254.35.55`.
2. **Confirmed Campaign Links**:
    * **Virgilian.com**: Confirmed present (First seen: 2026-01-11).
    * **Dollicons.com**: Confirmed present (First seen: 2026-02-11 - *Brand new*).
    * **Other Known Actors**: `livinitlarge.net` (Seen 2024-2026), `rustyload.com`, `starmail.net`.
3. **Infrastructure Consistency**:
    * **ASN**: Consistently AS16276 (OVH).
    * **Nameserver Reputation**: Many domains show `ns_reputation_score: 69`, suggesting a shared, potentially low-reputation nameserver infrastructure.
    * **Mail Infrastructure**: The `in.mail.tm` MX record often correlates with this cluster (as seen in previous analysis), though this CSV focuses on A-records pointing to the IP.
4. **Temporal Scope**:
    * Oldest distinct activity in this snapshot goes back to at least 2020 (`55.ip-51-254-35.eu`).
    * **Recent Surge**: High volume of "First Seen" dates in late 2025 and early 2026 (`virgilian.com`, `dollicons.com`, `trythe.net`), indicating an *active and accelerating* campaign.

## Domain Samples (Risk Score 69+)

* `dollicons.com`
* `virgilian.com`
* `livinitlarge.net`
* `rustyload.com`
* `soscandia.org`
* `starmail.net`
* `rowdydow.com`
* `arxxwalls.com`
* `workingtall.com`
* `splitparents.com`

## Recommendations

1. **Block IP**: `51.254.35.55` is confirmed hostile. Recommendation to block inbound traffic from this IP.
2. **Monitor ASN**: While OVH is large, this specific subnet (`51.254.35.0/24` or similar) should be scrutinized.
3. **Ingest Domains**: The domains found in this CSV should be added to the `dea_domains.csv` or `high_abuse_domains.csv` blocklists immediately.
