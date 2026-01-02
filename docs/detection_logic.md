# Vendor-Agnostic Detection Logic

This document outlines conceptual detection logic for email-based abuse, designed to be implemented in any SIEM (Splunk, ELK, Chronicle) or backend logic (Python, Go, etc.).

## Core Philosophy
**Indicators (Domains) rotate.**
**Infrastructure (MX/ASNs) persists.**

Detecting abuse requires a layered approach:
1.  **Blocklist**: Exact match on known lists processes 80% of volume.
2.  **Infrastructure Pivot**: Matches unknown domains using known-bad mail infrastructure.
3.  **Behavioral**: Velocity and context.

---

## 1. Login / Registration Detection

### Logic A: Strict Indicator Match
**Goal**: Block known disposable providers.
```pseudo
IF email_domain IN [dea_domains.csv]
AND email_domain NOT IN [dea_allowlist.csv]
THEN
    Action: BLOCK or REQUIRE_VERIFICATION
    Label: "Known Disposable Provider"
```

### Logic B: Infrastructure Family Match (The "Pivot")
**Goal**: Detect custom domains running on disposable infrastructure (e.g., a custom domain hosted on 10minutemail's server).
**Data Source**: `mx_counts.csv` (Top DEA MX Hosts)
```pseudo
Lookup email_domain MX records -> [current_mx_list]

IF ANY(current_mx_list) IN [Top_50_DEA_MX_Hosts from mx_counts.csv]
AND email_domain NOT IN [dea_domains.csv]
THEN
    Action: FLAG_HIGH_RISK
    Label: "Hidden Disposable Infrastructure"
    Reason: "Domain uses known burner MX ({matched_mx})"
```
> **Research Note**: This catches "private" burner domains that users register to bypass basic blocklists.

### Logic C: Hosting Provider Correlation
**Goal**: Identify low-reputation mail hosts (e.g., mail server running on a cheap VPS instead of Google/Outlook/Zoho).
**Data Source**: `risky_asn_list.csv`
```pseudo
Lookup email_domain A record -> [mx_ip]
enrich [mx_ip] -> [mx_asn]

IF [mx_asn] IN [risky_asn_list.csv] (e.g., DigitalOcean, OVH, CheapVPS)
AND email_domain NOT IN [Known_Corporate_List]
THEN
    Action: INCREASE_RISK_SCORE
    Label: "Low Reputation Mail Infrastructure"
```

---

## 2. Account Change Events (High Fidelity)

### Logic D: Email Change to DEA
**Context**: A user changing a valid email (`gmail.com`) to a disposable one (`sharklasers.com`) is a high-confidence ATO (Account Takeover) or fraud signal.

```pseudo
Event: User_Update_Email
  Old_Email_Domain: "gmail.com" (High Rep)
  New_Email_Domain: [Target]

CHECKS:
1. Is [Target] in [dea_domains.csv]?
   -> CRITICAL ALERT: "Downgrade to Disposable"

2. Is [Target] MX in [mx_counts.csv]?
   -> HIGH ALERT: "Downgrade to Disposable Infrastructure"
```

---

## 3. False Positive Controls

Always apply the Allowlist **last** to override detection.

```pseudo
IF email_domain IN [dea_allowlist.csv]
THEN
    Result: CLEARED (Legitimate)
    Reason: "Explicit Allowlist"
```
