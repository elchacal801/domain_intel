/**
 * Static registry of fingerprint and FLAME Threat Path definitions.
 * Sourced from config/fingerprints/*.yaml and AI briefing evidence data.
 */

export const fpRegistry = {
    'FP-0001': {
        name: 'OVH cPanel DEA Infrastructure',
        description: 'Bulk DEA domains hosted on OVH (ASN 16276) using cprapid.com nameservers and temp-mail-pro.com MX servers.',
    },
    'FP-0002': {
        name: 'Alibaba App Sideloading Infrastructure',
        description: 'Domains hosting non-standard MX infrastructure with app sideloading indicators (download, install, APK keywords).',
    },
    'FP-0003': {
        name: 'Crypto/Finance Fraud Co-hosting',
        description: 'Domains co-hosted on shared infrastructure exhibiting cryptocurrency or finance fraud patterns.',
    },
    'FP-0004': {
        name: 'GName Cloudflare China Hosting',
        description: 'Domains registered via GName registrar using Cloudflare infrastructure with China nexus indicators.',
    },
    'FP-0005': {
        name: 'GoDaddy Bulk Registration Pattern',
        description: 'Domains exhibiting bulk registration patterns via GoDaddy, often associated with domain warehousing or typosquat campaigns.',
    },
    'FP-0006': {
        name: 'Shell Domain MX Cluster',
        description: 'Domains sharing MX infrastructure in shell domain clusters — no web presence, configured only for mail reception.',
    },
    'FP-0007': {
        name: 'Typosquat Evasion Infrastructure',
        description: 'Confirmed typosquats (via dnstwist) exhibiting evasion: strategic redirects to brand, active MX, registrant mismatch, or sanctions matches.',
    },
};

export const tpRegistry = {
    'TP-0001': 'Brand impersonation typosquat — single-character deviation from major brands',
    'TP-0002': 'Insurance/healthcare brand typosquat cluster targeting Aetna and similar',
    'TP-0003': 'Bulk DEA hosting infrastructure on OVH using disposable MX',
    'TP-0005': 'Allstate brand typosquat cluster with character substitution',
    'TP-0010': 'GName registrar bulk registration with Cloudflare, China nexus',
    'TP-0012': 'Character-substitution typosquat targeting tier-1 brands (Google, Amazon)',
    'TP-0013': 'Adobe brand typosquat cluster with suffix/prefix manipulation',
    'TP-0015': 'High-confidence typosquat evidence cluster for financial/enterprise brands (BMO, Adobe)',
    'TP-0017': 'Numeric domain cluster on .xyz TLD — suspected automated registration',
    'TP-0019': 'Prefix-manipulation typosquat cluster targeting insurance brands',
};

/** Column header tooltips */
export const columnTooltips = {
    domain: 'Fully qualified domain name being investigated',
    fp_id: 'Infrastructure fingerprint ID — a pattern of shared hosting, registrar, or DNS indicators',
    confidence: 'Match confidence score (0-100%). Higher = stronger evidence the domain matches the fingerprint pattern',
    flame_tp_ids: 'FLAME Threat Path IDs — structured threat intelligence tracking identifiers',
    tld: 'Top-level domain extension (e.g. .com, .xyz, .info)',
    registrar: 'Domain registrar organization (from WHOIS/RDAP)',
};

/** KPI tooltips */
export const kpiTooltips = {
    total_domains: 'Total number of domains monitored in the pipeline, including all sources',
    matched_domains: 'Domains matching at least one infrastructure fingerprint pattern',
    unique_fingerprints: 'Number of distinct fingerprint patterns that matched at least one domain',
    total_clusters: 'Infrastructure clusters where ≥3 domains share MX, IP, or registrar+NS',
};
