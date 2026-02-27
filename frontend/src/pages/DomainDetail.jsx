import { useParams, Link } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { useData } from '@/context/DataContext';
import ConfidenceBadge from '@/components/ConfidenceBadge';
import FlameBadge from '@/components/FlameBadge';
import Section from '@/components/Section';

/* ---------- tiny helpers ---------- */

function Field({ label, value, mono }) {
  if (value == null || value === '' || value === 'N/A') return null;
  return (
    <div className="space-y-0.5">
      <dt className="text-xs font-medium uppercase tracking-wider text-gray-500">
        {label}
      </dt>
      <dd className={`text-sm text-gray-200 ${mono ? 'font-mono' : ''}`}>
        {String(value)}
      </dd>
    </div>
  );
}

function hasAny(obj, keys) {
  return keys.some(k => obj[k] != null && obj[k] !== '' && obj[k] !== 'N/A');
}

/* ---------- main component ---------- */

export default function DomainDetail() {
  const { domain } = useParams();
  const { loadDomains, domains } = useData();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setNotFound(false);
      const allDomains = domains || (await loadDomains());
      if (cancelled) return;
      const entry = allDomains[domain] || null;
      setData(entry);
      setNotFound(!entry);
      setLoading(false);
    }
    load();
    return () => { cancelled = true; };
  }, [domain, loadDomains, domains]);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center text-gray-400">
        Loading domain data...
      </div>
    );
  }

  if (notFound) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-4">
        <p className="text-gray-400">
          No data found for <span className="font-mono text-gray-200">{domain}</span>
        </p>
        <Link
          to="/investigate"
          className="text-sm text-blue-400 hover:text-blue-300"
        >
          Back to search
        </Link>
      </div>
    );
  }

  const d = data;
  const matches = d.matches || [];
  const highestScore =
    matches.length > 0
      ? Math.max(...matches.map(m => Number(m.confidence) || 0))
      : null;

  const flameTpIds = d.flame_tp_ids
    ? String(d.flame_tp_ids)
        .split(/[,;]+/)
        .map(s => s.trim())
        .filter(Boolean)
    : [];

  const showEntity = hasAny(d, [
    'os_match_score', 'os_entity_type', 'os_dataset', 'os_entity_id',
    'icij_match_score', 'icij_entity_match', 'icij_dataset', 'icij_jurisdiction',
    'gleif_lei', 'gleif_status', 'gleif_legal_name', 'gleif_jurisdiction',
  ]);

  const showAI = hasAny(d, [
    'ai_category', 'ai_confidence_score', 'dnstwist_match',
    'dnstwist_fuzzer', 'dnstwist_target', 'redirects_to_brand',
  ]);

  const showRisk = hasAny(d, ['risk_tags', 'rbl_hits', 'otx_risk']);

  return (
    <div className="space-y-6">
      {/* ---------- 1. Header ---------- */}
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="font-mono text-2xl font-bold text-gray-100">{domain}</h1>
        {highestScore != null && <ConfidenceBadge score={highestScore} />}
        {flameTpIds.map(tp => (
          <FlameBadge key={tp} tpId={tp} />
        ))}
      </div>

      {/* ---------- 2. Fingerprint Matches ---------- */}
      {matches.length > 0 && (
        <Section title="Fingerprint Matches">
          <div className="space-y-3">
            {matches.map((m, i) => (
              <MatchCard key={`${m.fp_id}-${i}`} match={m} />
            ))}
          </div>
        </Section>
      )}

      {/* ---------- 3. Entity Screening ---------- */}
      {showEntity && (
        <Section title="Entity Screening">
          <div className="grid gap-4 sm:grid-cols-3">
            {/* OpenSanctions */}
            <div className="rounded-md border border-border-subtle bg-gray-950 p-3">
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-red-400">
                OpenSanctions
              </h4>
              <dl className="space-y-2">
                <Field label="Match Score" value={d.os_match_score} />
                <Field label="Entity Type" value={d.os_entity_type} />
                <Field label="Dataset" value={d.os_dataset} />
                <Field label="Entity ID" value={d.os_entity_id} mono />
              </dl>
            </div>

            {/* ICIJ */}
            <div className="rounded-md border border-border-subtle bg-gray-950 p-3">
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-yellow-400">
                ICIJ
              </h4>
              <dl className="space-y-2">
                <Field label="Match Score" value={d.icij_match_score} />
                <Field label="Entity Match" value={d.icij_entity_match} />
                <Field label="Dataset" value={d.icij_dataset} />
                <Field label="Jurisdiction" value={d.icij_jurisdiction} />
              </dl>
            </div>

            {/* GLEIF */}
            <div className="rounded-md border border-border-subtle bg-gray-950 p-3">
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-green-400">
                GLEIF
              </h4>
              <dl className="space-y-2">
                <Field label="LEI" value={d.gleif_lei} mono />
                <Field label="Status" value={d.gleif_status} />
                <Field label="Legal Name" value={d.gleif_legal_name} />
                <Field label="Jurisdiction" value={d.gleif_jurisdiction} />
              </dl>
            </div>
          </div>
        </Section>
      )}

      {/* ---------- 4. DNS Infrastructure ---------- */}
      <Section title="DNS Infrastructure">
        <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Primary MX" value={d.primary_mx} mono />
          <Field label="MX IP" value={d.mx_ip} mono />
          <Field label="ASN" value={d.asn ? `${d.asn} - ${d.asn_name || ''}` : d.asn_name} mono />
          <Field label="BGP Prefix" value={d.bgp_prefix} mono />
          <Field label="Nameservers" value={d.nameservers} mono />
          <Field label="Country" value={d.cc} />
          <Field label="MX Records" value={d.mx_records} mono />
        </dl>
      </Section>

      {/* ---------- 5. AI Classification ---------- */}
      {showAI && (
        <Section title="AI Classification">
          <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Field label="Category" value={d.ai_category} />
            <Field label="AI Confidence" value={d.ai_confidence_score} />
            <Field label="DNSTwist Match" value={d.dnstwist_match} />
            <Field label="DNSTwist Fuzzer" value={d.dnstwist_fuzzer} />
            <Field label="DNSTwist Target" value={d.dnstwist_target} mono />
            <Field label="Redirects to Brand" value={d.redirects_to_brand} />
          </dl>
        </Section>
      )}

      {/* ---------- 6. WHOIS / RDAP ---------- */}
      <Section title="WHOIS / RDAP">
        <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="Registrant Org" value={d.registrant_org} />
          <Field label="Creation Date" value={d.creation_date} />
          <Field label="Age (days)" value={d.age_days} />
          <Field label="Registry" value={d.registry} />
          <Field label="SSL Present" value={d.ssl_present} />
          <Field label="Registrant Mismatch" value={d.registrant_mismatch} />
        </dl>
      </Section>

      {/* ---------- 7. Web Probe ---------- */}
      <Section title="Web Probe">
        <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="HTTP Status" value={d.http_status} mono />
          <Field label="HTTP Title" value={d.http_title} />
          <Field label="HTTP Server" value={d.http_server} mono />
          <Field label="HTTPS Status" value={d.https_status} mono />
          <Field label="HTTPS Title" value={d.https_title} />
          <Field label="HTTPS Server" value={d.https_server} mono />
          <Field label="Redirect Target" value={d.http_redirect_target} mono />
        </dl>
      </Section>

      {/* ---------- 8. Risk & Reputation ---------- */}
      {showRisk && (
        <Section title="Risk & Reputation">
          <dl className="grid gap-4 sm:grid-cols-3">
            <Field label="Risk Tags" value={d.risk_tags} />
            <Field label="RBL Hits" value={d.rbl_hits} />
            <Field label="OTX Risk" value={d.otx_risk} />
          </dl>
        </Section>
      )}
    </div>
  );
}

/* ---------- MatchCard sub-component ---------- */

function MatchCard({ match }) {
  const [expanded, setExpanded] = useState(false);
  const m = match;

  let evidenceContent = null;
  if (m.evidence) {
    try {
      evidenceContent =
        typeof m.evidence === 'string'
          ? JSON.stringify(JSON.parse(m.evidence), null, 2)
          : JSON.stringify(m.evidence, null, 2);
    } catch {
      evidenceContent = String(m.evidence);
    }
  }

  return (
    <div className="rounded-md border border-border-subtle bg-gray-950 p-3">
      <div className="flex flex-wrap items-center gap-3">
        <span className="font-mono text-sm font-medium text-blue-400">
          {m.fp_id}
        </span>
        <span className="text-sm text-gray-200">{m.fp_name}</span>
        <ConfidenceBadge score={m.confidence} />
        {evidenceContent && (
          <button
            onClick={() => setExpanded(prev => !prev)}
            className="ml-auto text-xs text-gray-400 hover:text-gray-200"
          >
            {expanded ? 'Hide evidence' : 'Show evidence'}
          </button>
        )}
      </div>
      {expanded && evidenceContent && (
        <pre className="mt-3 max-h-64 overflow-auto rounded bg-gray-900 p-3 font-mono text-xs text-gray-300">
          {evidenceContent}
        </pre>
      )}
    </div>
  );
}
