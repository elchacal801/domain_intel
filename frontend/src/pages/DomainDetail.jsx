import { useParams, Link } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { useData } from '@/context/DataContext';
import ConfidenceBadge from '@/components/ConfidenceBadge';
import FlameBadge from '@/components/FlameBadge';
import Section from '@/components/Section';
import {
  ArrowLeft, Fingerprint, ShieldAlert, Globe, Brain, FileKey, Activity,
  AlertTriangle, Server, Network, ExternalLink,
} from 'lucide-react';

/* ---------- tiny helpers ---------- */

function Field({ label, value, mono }) {
  if (value == null || value === '' || value === 'N/A') return null;
  return (
    <div className="space-y-1">
      <dt className="text-[10px] font-semibold uppercase tracking-widest text-gray-500">
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
  const { loadDomain } = useData();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setNotFound(false);
      const entry = await loadDomain(domain);
      if (cancelled) return;
      setData(entry);
      setNotFound(!entry);
      setLoading(false);
    }
    load();
    return () => { cancelled = true; };
  }, [domain, loadDomain]);

  if (loading) {
    return (
      <div className="flex h-80 items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="h-10 w-10 animate-spin rounded-full border-2 border-blue-500/30 border-t-blue-500" />
          <span className="text-sm text-gray-500">Loading domain data…</span>
        </div>
      </div>
    );
  }

  if (notFound) {
    return (
      <div className="flex h-80 flex-col items-center justify-center gap-4">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gray-800/50">
          <Globe className="h-8 w-8 text-gray-600" />
        </div>
        <p className="text-gray-400">
          No data found for <span className="font-mono text-gray-200">{domain}</span>
        </p>
        <Link to="/investigate" className="flex items-center gap-1.5 text-sm text-blue-400 hover:text-blue-300 transition-colors">
          <ArrowLeft className="h-4 w-4" />
          Back to search
        </Link>
      </div>
    );
  }

  const d = data;
  const matches = d.matches || [];
  const highestScore = matches.length > 0 ? Math.max(...matches.map(m => Number(m.confidence) || 0)) : null;

  const flameTpIds = d.flame_tp_ids
    ? String(d.flame_tp_ids).split(/[,;]+/).map(s => s.trim()).filter(Boolean)
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
    <div className="space-y-5 animate-fade-in">
      {/* ---------- Back link ---------- */}
      <Link to="/investigate" className="inline-flex items-center gap-1.5 text-sm text-gray-500 transition-colors hover:text-blue-400">
        <ArrowLeft className="h-4 w-4" />
        Back to search
      </Link>

      {/* ---------- 1. Header ---------- */}
      <div className="glass-card p-6">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl"
            style={{ background: 'linear-gradient(135deg, #1e3a5f, #1d4ed8)' }}
          >
            <Globe className="h-5 w-5 text-blue-300" />
          </div>
          <h1 className="font-mono text-2xl font-bold text-gray-100">{domain}</h1>
          {highestScore != null && <ConfidenceBadge score={highestScore} />}
          {flameTpIds.map(tp => <FlameBadge key={tp} tpId={tp} />)}
        </div>
      </div>

      {/* ---------- 2. Fingerprint Matches ---------- */}
      {matches.length > 0 && (
        <Section
          title="Fingerprint Matches"
          icon={<Fingerprint className="h-4 w-4 text-orange-400" />}
          accentColor="#f97316"
        >
          <div className="space-y-3">
            {matches.map((m, i) => (
              <MatchCard key={`${m.fp_id}-${i}`} match={m} />
            ))}
          </div>
        </Section>
      )}

      {/* ---------- 3. Entity Screening ---------- */}
      {showEntity && (
        <Section
          title="Entity Screening"
          icon={<ShieldAlert className="h-4 w-4 text-red-400" />}
          accentColor="#ef4444"
        >
          <div className="grid gap-4 sm:grid-cols-3">
            <EntityCard
              title="OpenSanctions" titleColor="#ef4444"
              fields={[
                { label: 'Match Score', value: d.os_match_score },
                { label: 'Entity Type', value: d.os_entity_type },
                { label: 'Dataset', value: d.os_dataset },
                { label: 'Entity ID', value: d.os_entity_id, mono: true },
              ]}
            />
            <EntityCard
              title="ICIJ" titleColor="#eab308"
              fields={[
                { label: 'Match Score', value: d.icij_match_score },
                { label: 'Entity Match', value: d.icij_entity_match },
                { label: 'Dataset', value: d.icij_dataset },
                { label: 'Jurisdiction', value: d.icij_jurisdiction },
              ]}
            />
            <EntityCard
              title="GLEIF" titleColor="#22c55e"
              fields={[
                { label: 'LEI', value: d.gleif_lei, mono: true },
                { label: 'Status', value: d.gleif_status },
                { label: 'Legal Name', value: d.gleif_legal_name },
                { label: 'Jurisdiction', value: d.gleif_jurisdiction },
              ]}
            />
          </div>
        </Section>
      )}

      {/* ---------- 4. DNS Infrastructure ---------- */}
      <Section
        title="DNS Infrastructure"
        icon={<Server className="h-4 w-4 text-blue-400" />}
        accentColor="#3b82f6"
      >
        <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Primary MX" value={d.primary_mx} mono />
          <Field label="MX IP" value={d.mx_ip} mono />
          <Field label="ASN" value={d.asn ? `${d.asn} — ${d.asn_name || ''}` : d.asn_name} mono />
          <Field label="BGP Prefix" value={d.bgp_prefix} mono />
          <Field label="Nameservers" value={d.nameservers} mono />
          <Field label="Country" value={d.cc} />
          <Field label="MX Records" value={d.mx_records} mono />
        </dl>
      </Section>

      {/* ---------- 5. AI Classification ---------- */}
      {showAI && (
        <Section
          title="AI Classification"
          icon={<Brain className="h-4 w-4 text-purple-400" />}
          accentColor="#a855f7"
        >
          <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
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
      <Section
        title="WHOIS / RDAP"
        icon={<FileKey className="h-4 w-4 text-cyan-400" />}
        accentColor="#06b6d4"
      >
        <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="Registrant Org" value={d.registrant_org} />
          <Field label="Creation Date" value={d.creation_date} />
          <Field label="Age (days)" value={d.age_days} />
          <Field label="Registry" value={d.registry} />
          <Field label="SSL Present" value={d.ssl_present} />
          <Field label="Registrant Mismatch" value={d.registrant_mismatch} />
        </dl>
      </Section>

      {/* ---------- 7. Web Probe ---------- */}
      <Section
        title="Web Probe"
        icon={<ExternalLink className="h-4 w-4 text-emerald-400" />}
        accentColor="#10b981"
      >
        <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-4">
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
        <Section
          title="Risk & Reputation"
          icon={<AlertTriangle className="h-4 w-4 text-amber-400" />}
          accentColor="#f59e0b"
        >
          <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-3">
            <Field label="Risk Tags" value={d.risk_tags} />
            <Field label="RBL Hits" value={d.rbl_hits} />
            <Field label="OTX Risk" value={d.otx_risk} />
          </dl>
        </Section>
      )}
    </div>
  );
}

/* ---------- EntityCard sub-component ---------- */

function EntityCard({ title, titleColor, fields }) {
  const hasData = fields.some(f => f.value != null && f.value !== '' && f.value !== 'N/A');
  if (!hasData) return (
    <div className="rounded-xl border border-border-subtle p-4" style={{ background: 'rgba(11, 17, 32, 0.6)' }}>
      <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider" style={{ color: titleColor }}>{title}</h4>
      <p className="text-xs text-gray-600">No data</p>
    </div>
  );

  return (
    <div className="rounded-xl border border-border-subtle p-4" style={{ background: 'rgba(11, 17, 32, 0.6)' }}>
      <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider" style={{ color: titleColor }}>{title}</h4>
      <dl className="space-y-2">
        {fields.map(f => <Field key={f.label} {...f} />)}
      </dl>
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
    <div className="rounded-xl border border-border-subtle p-4 transition-colors hover:border-orange-500/20"
      style={{ background: 'rgba(11, 17, 32, 0.5)' }}
    >
      <div className="flex flex-wrap items-center gap-3">
        <span className="rounded-md bg-orange-500/10 px-2.5 py-0.5 font-mono text-sm font-medium text-orange-400">
          {m.fp_id}
        </span>
        <span className="text-sm text-gray-300">{m.fp_name}</span>
        <ConfidenceBadge score={m.confidence} />
        {evidenceContent && (
          <button
            onClick={() => setExpanded(prev => !prev)}
            className="ml-auto text-xs text-gray-500 transition-colors hover:text-blue-400"
          >
            {expanded ? 'Hide evidence ▲' : 'Show evidence ▼'}
          </button>
        )}
      </div>
      {expanded && evidenceContent && (
        <pre className="mt-3 max-h-64 overflow-auto rounded-lg p-4 font-mono text-xs text-gray-400 animate-slide-down"
          style={{ background: 'rgba(6, 10, 20, 0.8)', border: '1px solid rgba(56, 78, 122, 0.2)' }}
        >
          {evidenceContent}
        </pre>
      )}
    </div>
  );
}
