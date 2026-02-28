import { useParams, Link } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { useData } from '@/context/DataContext';
import ConfidenceBadge from '@/components/ConfidenceBadge';
import FlameBadge from '@/components/FlameBadge';
import Section from '@/components/Section';
import Tooltip from '@/components/Tooltip';
import {
  ArrowLeft, Fingerprint, ShieldAlert, Globe, Brain, FileKey, Activity,
  AlertTriangle, Server, Network, ExternalLink, Copy, Check,
} from 'lucide-react';

/* ---- helper ---- */
function Field({ label, value, mono }) {
  if (value == null || value === '' || value === 'N/A') return null;
  return (
    <div className="space-y-0.5">
      <dt className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">{label}</dt>
      <dd className={`text-sm text-text-secondary ${mono ? 'font-mono' : ''}`}>{String(value)}</dd>
    </div>
  );
}

function hasAny(obj, keys) {
  return keys.some(k => obj[k] != null && obj[k] !== '' && obj[k] !== 'N/A');
}

export default function DomainDetail() {
  const { domain } = useParams();
  const { loadDomain } = useData();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true); setNotFound(false);
      const entry = await loadDomain(domain);
      if (cancelled) return;
      setData(entry); setNotFound(!entry); setLoading(false);
    }
    load();
    return () => { cancelled = true; };
  }, [domain, loadDomain]);

  function copyDomain() {
    navigator.clipboard.writeText(domain);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  if (loading) {
    return (
      <div className="flex h-80 items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-7 w-7 animate-spin rounded-full border-2 border-white/10 border-t-white/50" />
          <span className="text-xs text-text-muted">Loading domain data…</span>
        </div>
      </div>
    );
  }

  if (notFound) {
    return (
      <div className="flex h-80 flex-col items-center justify-center gap-3">
        <Globe className="h-8 w-8 text-white/10" />
        <p className="text-sm text-text-muted">No data for <span className="font-mono text-text-secondary">{domain}</span></p>
        <Link to="/investigate" className="flex items-center gap-1 text-xs text-text-muted hover:text-text-primary transition-colors">
          <ArrowLeft className="h-3.5 w-3.5" /> Back to search
        </Link>
      </div>
    );
  }

  const d = data;
  const matches = d.matches || [];
  const highestScore = matches.length > 0 ? Math.max(...matches.map(m => Number(m.confidence) || 0)) : null;
  const flameTpIds = d.flame_tp_ids
    ? String(d.flame_tp_ids).split(/[,;]+/).map(s => s.trim()).filter(Boolean) : [];

  const showEntity = hasAny(d, ['os_match_score', 'os_entity_type', 'os_dataset', 'icij_match_score', 'icij_entity_match', 'gleif_lei', 'gleif_status']);
  const showAI = hasAny(d, ['ai_category', 'ai_confidence_score', 'dnstwist_match', 'dnstwist_fuzzer', 'dnstwist_target', 'redirects_to_brand']);
  const showRisk = hasAny(d, ['risk_tags', 'rbl_hits', 'otx_risk']);

  return (
    <div className="space-y-4 animate-fade-in">
      <Link to="/investigate" className="inline-flex items-center gap-1 text-xs text-text-muted hover:text-text-primary transition-colors">
        <ArrowLeft className="h-3.5 w-3.5" /> Back
      </Link>

      {/* Header */}
      <div className="glass-card p-5">
        <div className="flex flex-wrap items-center gap-3">
          <Globe className="h-5 w-5 text-white/25" />
          <h1 className="font-mono text-xl font-bold text-text-primary">{domain}</h1>
          <button onClick={copyDomain} className="rounded border border-border-subtle p-1 text-text-muted hover:text-text-primary transition-colors" title="Copy domain">
            {copied ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
          </button>
          {highestScore != null && <ConfidenceBadge score={highestScore} />}
          {flameTpIds.map(tp => <FlameBadge key={tp} tpId={tp} />)}
        </div>
      </div>

      {/* Fingerprint Matches */}
      {matches.length > 0 && (
        <Section title="Fingerprint Matches" icon={<Fingerprint className="h-3.5 w-3.5 text-fp" />} accentColor="rgba(249,115,22,0.2)">
          <div className="space-y-2">
            {matches.map((m, i) => <MatchCard key={`${m.fp_id}-${i}`} match={m} />)}
          </div>
        </Section>
      )}

      {/* Entity Screening */}
      {showEntity && (
        <Section title="Entity Screening" icon={<ShieldAlert className="h-3.5 w-3.5 text-risk-high/50" />} accentColor="rgba(239,68,68,0.15)">
          <div className="grid gap-3 sm:grid-cols-3">
            <EntityCard title="OpenSanctions" titleColor="#ef4444" fields={[
              { label: 'Score', value: d.os_match_score }, { label: 'Type', value: d.os_entity_type },
              { label: 'Dataset', value: d.os_dataset }, { label: 'Entity ID', value: d.os_entity_id, mono: true },
            ]} />
            <EntityCard title="ICIJ" titleColor="#eab308" fields={[
              { label: 'Score', value: d.icij_match_score }, { label: 'Match', value: d.icij_entity_match },
              { label: 'Dataset', value: d.icij_dataset }, { label: 'Jurisdiction', value: d.icij_jurisdiction },
            ]} />
            <EntityCard title="GLEIF" titleColor="#22c55e" fields={[
              { label: 'LEI', value: d.gleif_lei, mono: true }, { label: 'Status', value: d.gleif_status },
              { label: 'Name', value: d.gleif_legal_name }, { label: 'Jurisdiction', value: d.gleif_jurisdiction },
            ]} />
          </div>
        </Section>
      )}

      {/* DNS */}
      <Section title="DNS Infrastructure" icon={<Server className="h-3.5 w-3.5 text-mx/50" />} accentColor="rgba(59,130,246,0.12)">
        <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Primary MX" value={d.primary_mx} mono /><Field label="MX IP" value={d.mx_ip} mono />
          <Field label="ASN" value={d.asn ? `${d.asn} — ${d.asn_name || ''}` : d.asn_name} mono />
          <Field label="BGP Prefix" value={d.bgp_prefix} mono /><Field label="Nameservers" value={d.nameservers} mono />
          <Field label="Country" value={d.cc} /><Field label="MX Records" value={d.mx_records} mono />
        </dl>
      </Section>

      {/* AI */}
      {showAI && (
        <Section title="AI Classification" icon={<Brain className="h-3.5 w-3.5 text-purple-400/50" />} accentColor="rgba(168,85,247,0.12)">
          <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-3">
            <Field label="Category" value={d.ai_category} /><Field label="AI Confidence" value={d.ai_confidence_score} />
            <Field label="DNSTwist Match" value={d.dnstwist_match} /><Field label="Fuzzer" value={d.dnstwist_fuzzer} />
            <Field label="Target" value={d.dnstwist_target} mono /><Field label="Redirects to Brand" value={d.redirects_to_brand} />
          </dl>
        </Section>
      )}

      {/* WHOIS */}
      <Section title="WHOIS / RDAP" icon={<FileKey className="h-3.5 w-3.5 text-cyan-400/50" />} accentColor="rgba(6,182,212,0.12)">
        <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="Registrant Org" value={d.registrant_org} /><Field label="Creation Date" value={d.creation_date} />
          <Field label="Age (days)" value={d.age_days} /><Field label="Registry" value={d.registry} />
          <Field label="SSL Present" value={d.ssl_present} /><Field label="Registrant Mismatch" value={d.registrant_mismatch} />
        </dl>
      </Section>

      {/* Web Probe */}
      <Section title="Web Probe" icon={<ExternalLink className="h-3.5 w-3.5 text-emerald-400/50" />} accentColor="rgba(16,185,129,0.12)">
        <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="HTTP Status" value={d.http_status} mono /><Field label="HTTP Title" value={d.http_title} />
          <Field label="HTTP Server" value={d.http_server} mono /><Field label="HTTPS Status" value={d.https_status} mono />
          <Field label="HTTPS Title" value={d.https_title} /><Field label="HTTPS Server" value={d.https_server} mono />
          <Field label="Redirect" value={d.http_redirect_target} mono />
        </dl>
      </Section>

      {/* Risk */}
      {showRisk && (
        <Section title="Risk & Reputation" icon={<AlertTriangle className="h-3.5 w-3.5 text-amber-400/50" />} accentColor="rgba(245,158,11,0.12)">
          <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-3">
            <Field label="Risk Tags" value={d.risk_tags} /><Field label="RBL Hits" value={d.rbl_hits} /><Field label="OTX Risk" value={d.otx_risk} />
          </dl>
        </Section>
      )}
    </div>
  );
}

function EntityCard({ title, titleColor, fields }) {
  const hasData = fields.some(f => f.value != null && f.value !== '' && f.value !== 'N/A');
  return (
    <div className="rounded-lg border border-border-subtle bg-[#0a0a0a] p-3.5">
      <h4 className="mb-2 text-[10px] font-semibold uppercase tracking-wider" style={{ color: titleColor }}>{title}</h4>
      {!hasData ? <p className="text-[10px] text-text-muted">No data</p> : (
        <dl className="space-y-1.5">{fields.map(f => <Field key={f.label} {...f} />)}</dl>
      )}
    </div>
  );
}

function MatchCard({ match }) {
  const [expanded, setExpanded] = useState(false);
  const m = match;
  let evidence = null;
  if (m.evidence) {
    try { evidence = typeof m.evidence === 'string' ? JSON.stringify(JSON.parse(m.evidence), null, 2) : JSON.stringify(m.evidence, null, 2); }
    catch { evidence = String(m.evidence); }
  }
  return (
    <div className="rounded-lg border border-border-subtle bg-[#0a0a0a] p-3 hover:border-border-hover transition-colors">
      <div className="flex flex-wrap items-center gap-2">
        <Tooltip text={`Fingerprint pattern match`}>
          <span className="rounded bg-orange-500/8 px-2 py-0.5 font-mono text-xs font-medium text-fp/80">{m.fp_id}</span>
        </Tooltip>
        <span className="text-xs text-text-secondary">{m.fp_name}</span>
        <ConfidenceBadge score={m.confidence} fpId={m.fp_id} />
        {evidence && (
          <button onClick={() => setExpanded(p => !p)} className="ml-auto text-[10px] text-text-muted hover:text-text-primary transition-colors">
            {expanded ? 'Hide ▲' : 'Evidence ▼'}
          </button>
        )}
      </div>
      {expanded && evidence && (
        <pre className="mt-2 max-h-48 overflow-auto rounded bg-[#080808] border border-border-subtle p-3 font-mono text-[10px] text-text-muted animate-slide-down">{evidence}</pre>
      )}
    </div>
  );
}
