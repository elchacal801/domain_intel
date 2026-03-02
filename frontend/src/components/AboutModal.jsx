import { useEffect, useRef } from 'react';
import { X, Shield, Globe, Fingerprint, Network, Search, Brain, Target, Flame } from 'lucide-react';

const SECTIONS = [
  {
    icon: Shield,
    title: 'What is Domain Intel?',
    content:
      'Domain Intel is a threat intelligence platform purpose-built for detecting and investigating disposable email address (DEA) providers, typosquatting campaigns, and high-abuse domain infrastructure. It moves beyond static blocklists by correlating domains through shared infrastructure — mail servers, web hosting IPs, registrars, and name servers — to map threat actor networks at scale.',
  },
  {
    icon: Target,
    title: 'Operational Intent',
    content:
      'This platform supports defensive security operations: fraud prevention, brand protection, and detection engineering. It automates the collection, enrichment, and classification pipeline that analysts would otherwise perform manually — ingesting 200k+ domains daily from open-source feeds, enriching them with DNS, ASN, WHOIS, and reputation data, then applying AI-driven classification to surface the highest-risk threats.',
  },
  {
    icon: Network,
    title: 'Methodology',
    items: [
      { label: 'Discovery', detail: 'Aggregate domains from open-source abuse feeds, Certificate Transparency logs, typosquat generation (DNSTwist), and malicious ad scanning (SEADS).' },
      { label: 'Triage', detail: 'Heuristic funnel reduces 200k+ domains to ~10k high-priority candidates using keyword matching and target similarity scoring.' },
      { label: 'Enrichment', detail: 'Bulk DNS resolution (MX, NS, A-records), Team Cymru ASN lookups, Shodan vulnerability scanning, and WHOIS registrar data — all with rate limiting and caching.' },
      { label: 'Clustering', detail: 'Domains are grouped by shared infrastructure pivots (MX hosts, MX IPs, web hosting IPs, registrar+NS). Known shared providers (Cloudflare, Google, AWS) are detected via ASN and pattern matching, with cluster confidence scored using inverted semantics for web hosting.' },
      { label: 'AI Classification', detail: 'LLM-based analysis (Claude/Gemini/GPT fallback chain) classifies site intent and detects semantic typosquats that evade regex-based detection.' },
      { label: 'Pivoting', detail: 'Reverse WHOIS (Whoxy) and Passive DNS (AlienVault OTX) turn individual bad domains into maps of the actor\'s entire network.' },
    ],
  },
  {
    icon: Fingerprint,
    title: 'YAML-Driven Fingerprinting',
    content:
      'The Matches page shows domains matching YAML-defined fingerprint rules. Each fingerprint defines required indicators (gates) and optional confidence modifiers. Fingerprints detect patterns like OVH-hosted cPanel DEA infrastructure, Alibaba sideloading networks, and crypto co-hosting clusters. Confidence scores reflect how many optional indicators matched beyond the required gates.',
  },
  {
    icon: Fingerprint,
    title: 'Active Fingerprints',
    note: 'Auto-generated from YAML definitions in config/fingerprints/.',
    items: [
      { label: 'FP-0001 — OVH cPanel DEA Infrastructure', detail: 'Bulk DEA domains on OVH (ASN 16276) using cprapid.com nameservers and temp-mail-pro.com MX.' },
      { label: 'FP-0002 — Alibaba App Sideloading', detail: 'Domains on Alibaba Cloud (ASN 45102) with app sideloading/download keywords, common for malicious APK distribution.' },
      { label: 'FP-0003 — Crypto/Finance Fraud Co-hosting', detail: 'Financial/crypto keyword domains hosted alongside DEA-pattern MX, common for investment scam infrastructure.' },
      { label: 'FP-0004 — Gname + Cloudflare China Hosting', detail: 'Gname registrar + Cloudflare NS + Chinese hosting ASN, a pattern seen in bulk fraud domain registration campaigns.' },
      { label: 'FP-0005 — GoDaddy Bulk Registration', detail: 'GoDaddy registrations with bulk registration indicators, associated with mass domain registration for fraud campaigns.' },
      { label: 'FP-0006 — Coordinated Shell Domain Network', detail: 'Domains sharing non-standard MX infrastructure with no web content and short registration age, indicating coordinated shell networks.' },
      { label: 'FP-0007 — Typosquat Evasion Infrastructure', detail: 'dnstwist-confirmed typosquats exhibiting evasion behaviors: strategic redirects, active MX, registrant mismatch, or sanctions matches.' },
    ],
  },
  {
    icon: Search,
    title: 'Investigation Workflow',
    items: [
      { label: 'Matches', detail: 'Start here — browse fingerprint-matched domains sorted by confidence. Filter by fingerprint ID, TLD, or registrar.' },
      { label: 'Investigate', detail: 'Search any domain to view its full profile: DNS records, ASN, MX/A-record resolution chains, shared infrastructure banners, risk tags, and AI classification.' },
      { label: 'Clusters', detail: 'Explore infrastructure clusters as interactive graphs. Nodes represent domains and shared infrastructure (MX hosts, MX IPs, web hosting IPs). High-confidence clusters on unknown infrastructure signal campaign activity.' },
      { label: 'Intel Briefing', detail: 'AI-generated daily intelligence summary highlighting new threats, campaign activity, and FLAME evidence candidates.' },
    ],
  },
  {
    icon: Brain,
    title: 'Key CTI Concepts',
    items: [
      { label: 'Inverted Confidence', detail: 'For web hosting (A-record) clusters, large size on unknown IPs indicates dedicated campaign infrastructure — the opposite of MX clusters where large size typically means shared hosting noise.' },
      { label: 'Resolution Chains', detail: 'Visual traces showing how a domain resolves: Domain \u2192 MX Host \u2192 MX IP \u2192 ASN, or Domain \u2192 A Record \u2192 ASN. These chains reveal shared infrastructure.' },
      { label: 'Shared Infrastructure', detail: 'Clusters on known providers (Cloudflare, Google, AWS) are scored LOW confidence — the shared hosting creates co-location, not operational linkage.' },
      { label: 'FLAME Integration', detail: 'FLAME (Fraud Lead Analysis & Mitigation Evidence) is a structured threat intelligence framework that maps technical indicators — domains, IPs, infrastructure patterns — to numbered Threat Paths (TP-XXXX). Each fingerprint match links to one or more Threat Paths, creating an evidence chain from raw domain data to actionable fraud intelligence. Threat Paths represent specific campaign patterns (e.g., TP-0003 = bulk DEA hosting on OVH, TP-0012 = tier-1 brand typosquats).' },
    ],
  },
  {
    icon: Flame,
    title: 'FLAME Framework',
    content:
      'FLAME (Fraud Lead Analysis & Mitigation Evidence) is the structured evidence framework that powers Domain Intel\'s threat intelligence output. It maps technical indicators discovered through enrichment and fingerprinting into numbered Threat Paths (TP-XXXX), each representing a specific fraud campaign pattern. Analysts use FLAME packages to build cases, track campaigns over time, and share structured intelligence across teams.',
    link: { url: 'https://elchacal801.github.io/flame-fraud/', text: 'View the FLAME Framework \u2192' },
  },
];

export default function AboutModal({ open, onClose }) {
  const overlayRef = useRef(null);
  const panelRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    const handle = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handle);
    return () => document.removeEventListener('keydown', handle);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      ref={overlayRef}
      onClick={(e) => { if (e.target === overlayRef.current) onClose(); }}
      className="fixed inset-0 z-[200] flex items-start justify-center overflow-y-auto py-12 px-4"
      style={{ background: 'rgba(0, 0, 0, 0.6)', backdropFilter: 'blur(4px)', animation: 'fadeIn 0.2s ease-out' }}
    >
      <div
        ref={panelRef}
        className="relative w-full max-w-2xl rounded-xl border animate-fade-in"
        style={{
          background: 'var(--bg-surface)',
          borderColor: 'var(--border-subtle)',
        }}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b px-6 py-4" style={{ borderColor: 'var(--border-subtle)' }}>
          <div className="flex items-center gap-2.5">
            <Globe className="h-5 w-5" style={{ color: 'var(--text-muted)' }} />
            <span className="text-sm font-medium tracking-tight" style={{ color: 'var(--text-primary)' }}>
              About Domain Intel
            </span>
          </div>
          <button
            onClick={onClose}
            className="theme-toggle"
            title="Close"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* Body */}
        <div className="space-y-5 px-6 py-5 max-h-[70vh] overflow-y-auto">
          {SECTIONS.map((section, idx) => {
            const Icon = section.icon;
            return (
              <div key={idx}>
                <div className="flex items-center gap-2 mb-2">
                  <Icon className="h-4 w-4 shrink-0" style={{ color: 'var(--text-muted)' }} />
                  <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-secondary)' }}>
                    {section.title}
                  </h3>
                </div>
                {section.content && (
                  <p className="text-xs leading-relaxed pl-6" style={{ color: 'var(--text-body)' }}>
                    {section.content}
                  </p>
                )}
                {section.note && (
                  <p className="text-[10px] italic pl-6 mt-1" style={{ color: 'var(--text-muted)' }}>
                    {section.note}
                  </p>
                )}
                {section.items && (
                  <div className="space-y-2 pl-6">
                    {section.items.map((item, i) => (
                      <div key={i}>
                        <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>
                          {item.label}
                        </span>
                        <span className="text-xs" style={{ color: 'var(--text-muted)' }}> — </span>
                        <span className="text-xs leading-relaxed" style={{ color: 'var(--text-body)' }}>
                          {item.detail}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
                {section.link && (
                  <div className="pl-6 mt-2">
                    <a
                      href={section.link.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs font-medium transition-colors hover:underline"
                      style={{ color: '#C0272D' }}
                    >
                      {section.link.text}
                    </a>
                  </div>
                )}
                {idx < SECTIONS.length - 1 && (
                  <div className="mt-4 border-b" style={{ borderColor: 'var(--border-subtle)' }} />
                )}
              </div>
            );
          })}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t px-6 py-3" style={{ borderColor: 'var(--border-subtle)' }}>
          <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
            For defensive research, fraud prevention, and detection engineering.
          </span>
          <a
            href="https://github.com/elchacal801/domain_intel"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[10px] font-medium hover:underline"
            style={{ color: 'var(--text-secondary)' }}
          >
            View on GitHub
          </a>
        </div>
      </div>
    </div>
  );
}
