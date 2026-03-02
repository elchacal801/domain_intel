/**
 * Auto-generated from config/fingerprints/*.yaml
 * Do not edit manually — run: python scripts/generate_fp_registry.py
 */

export const fpRegistry = {
    "FP-0001": {
        "name": "OVH cPanel DEA Infrastructure",
        "description": "Bulk DEA domains on OVH (ASN 16276) using cprapid.com nameservers and temp-mail-pro.com MX.",
        "flame_tp_ids": [
            "TP-0003"
        ]
    },
    "FP-0002": {
        "name": "Alibaba App Sideloading Infrastructure",
        "description": "Domains on Alibaba Cloud (ASN 45102) with app sideloading/download keywords, common for malicious APK distribution.",
        "flame_tp_ids": [
            "TP-0012"
        ]
    },
    "FP-0003": {
        "name": "Crypto/Finance Fraud Co-hosting",
        "description": "Domains with financial/crypto keywords in titles hosted alongside DEA-pattern MX, common for investment scam infrastructure.",
        "flame_tp_ids": [
            "TP-0017"
        ]
    },
    "FP-0004": {
        "name": "Gname Registrar + Cloudflare China Hosting",
        "description": "Domains registered through Gname using Cloudflare NS with Chinese hosting ASN, pattern seen in bulk fraud domain registration campaigns.",
        "flame_tp_ids": [
            "TP-0017"
        ]
    },
    "FP-0005": {
        "name": "GoDaddy Bulk Registration Pattern",
        "description": "Domains registered through GoDaddy with bulk registration indicators, pattern associated with mass domain registration for fraud campaigns.",
        "flame_tp_ids": [
            "TP-0019"
        ]
    },
    "FP-0006": {
        "name": "Coordinated Shell Domain Network (MX Clustering)",
        "description": "Domains sharing non-standard MX infrastructure with no web content and short registration age, indicating coordinated shell domain networks.",
        "flame_tp_ids": [
            "TP-0003"
        ]
    },
    "FP-0007": {
        "name": "Typosquat Evasion Infrastructure",
        "description": "Domains confirmed as typosquats (via dnstwist) exhibiting evasion behaviors: strategic redirects to brand, active MX, registrant mismatch, or sanctions matches.",
        "flame_tp_ids": [
            "TP-0012"
        ]
    }
};

// --- Static registries (maintained manually) ---

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
    entity_linked_clusters: 'Private infrastructure clusters where domains have sanctions, leak database, or legal entity screening hits',
};
