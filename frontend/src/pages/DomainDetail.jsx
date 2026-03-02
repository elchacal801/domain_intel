import { useParams, Link, useNavigate } from 'react-router-dom';
import { useState, useEffect, useMemo } from 'react';
import { useData } from '@/context/DataContext';
import ConfidenceBadge from '@/components/ConfidenceBadge';
import FlameBadge from '@/components/FlameBadge';
import Section from '@/components/Section';
import Tooltip from '@/components/Tooltip';
import DomainTimeline from '@/components/DomainTimeline';
import ResolutionChain from '@/components/ResolutionChain';
import SharedInfraBanner from '@/components/SharedInfraBanner';
import {
  ArrowLeft, Fingerprint, ShieldAlert, Globe, Brain, FileKey, Activity,
  AlertTriangle, Server, Network, ExternalLink, Copy, Check,
  Radar, Eye, Bug, Shield, Download, Users, Image, ArrowLeftRight, Clock,
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

function safe(v) {
  if (v == null) return null;
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

export default function DomainDetail() {
  const { domain } = useParams();
  const navigate = useNavigate();
  const { loadDomain, clusters } = useData();
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

  // Related domains from cluster data
  const relatedDomains = useMemo(() => {
    if (!clusters?.edges || !clusters?.nodes) return [];
    const domId = `dom:${domain}`;
    const infraIds = new Set();
    for (const e of clusters.edges) {
      if (e.source === domId) infraIds.add(e.target);
      if (e.target === domId) infraIds.add(e.source);
    }
    if (infraIds.size === 0) return [];
    const related = new Map();
    for (const e of clusters.edges) {
      if (infraIds.has(e.target) && e.source !== domId && e.source.startsWith('dom:')) {
        const d = e.source.slice(4);
        const infraNode = clusters.nodes.find(n => n.id === e.target);
        if (!related.has(d)) related.set(d, []);
        related.get(d).push(infraNode?.type || 'unknown');
      }
      if (infraIds.has(e.source) && e.target !== domId && e.target.startsWith('dom:')) {
        const d = e.target.slice(4);
        const infraNode = clusters.nodes.find(n => n.id === e.source);
        if (!related.has(d)) related.set(d, []);
        related.get(d).push(infraNode?.type || 'unknown');
      }
    }
    return [...related.entries()].slice(0, 20).map(([dom, types]) => ({ domain: dom, linkTypes: [...new Set(types)] }));
  }, [clusters, domain]);

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
  const matches = d?.matches || [];
  const highestScore = matches.length > 0 ? Math.max(...matches.map(m => Number(m?.confidence) || 0)) : null;
  const flameTpIds = d?.flame_tp_ids
    ? String(d.flame_tp_ids).split(/[,;]+/).map(s => s.trim()).filter(Boolean) : [];

  const showEntity = hasAny(d, ['os_match_score', 'os_entity_type', 'os_dataset', 'icij_match_score', 'icij_entity_match', 'gleif_lei', 'gleif_status']);
  const showAI = hasAny(d, ['ai_category', 'ai_confidence_score', 'dnstwist_match', 'dnstwist_fuzzer', 'dnstwist_target', 'redirects_to_brand']);
  const showRisk = hasAny(d, ['risk_tags', 'rbl_hits', 'otx_risk', 'risk_score']);
  const showShodan = hasAny(d, ['shodan_ports', 'shodan_vulns', 'shodan_os', 'shodan_tags', 'shodan_hostnames']);
  const showVT = hasAny(d, ['vt_malicious_count', 'vt_undetected_count', 'vt_last_analysis']);
  const showPhishTank = hasAny(d, ['phishtank_phishtank_url', 'phishtank_urlhaus_threat', 'phishtank_phishtank_match']);
  const showOpenClaw = hasAny(d, ['openclaw_agent_type', 'openclaw_exposure_level', 'openclaw_model_id']);

  // STIX export
  function exportStix() {
    const now = new Date().toISOString();
    const indicator = {
      type: 'indicator', spec_version: '2.1',
      id: `indicator--${crypto.randomUUID()}`,
      created: now, modified: now,
      name: `Suspicious domain: ${domain}`,
      pattern: `[domain-name:value = '${domain}']`,
      pattern_type: 'stix', valid_from: now,
      confidence: d.risk_score ? Number(d.risk_score) : 50,
    };
    const bundle = { type: 'bundle', id: `bundle--${crypto.randomUUID()}`, objects: [indicator] };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `${domain}_stix.json`; a.click();
    URL.revokeObjectURL(url);
  }

  const riskColor = d.risk_level === 'Critical' ? '#ef4444' : d.risk_level === 'High' ? '#f97316' : d.risk_level === 'Medium' ? '#eab308' : '#22c55e';

  return (
    <div className="space-y-4 animate-fade-in">
      <Link to="/investigate" className="inline-flex items-center gap-1 text-xs text-text-muted hover:text-text-primary transition-colors">
        <ArrowLeft className="h-3.5 w-3.5" /> Back
      </Link>

      {/* Header */}
      <div className="glass-card p-5">
        <div className="flex flex-wrap items-center gap-3">
          <Globe className="h-5 w-5 text-white/25" />
          <h1 className="font-mono text-xl font-bold text-text-primary">{safe(domain)}</h1>
          <button onClick={copyDomain} className="rounded border border-border-subtle p-1 text-text-muted hover:text-text-primary transition-colors" title="Copy domain">
            {copied ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
          </button>
          {highestScore != null && <ConfidenceBadge score={highestScore} />}
          {d.risk_score != null && (
            <Tooltip text={`Composite risk: ${d.risk_score}/100 (${d.risk_level})`}>
              <span className="rounded-full px-2.5 py-0.5 text-xs font-bold" style={{ background: `${riskColor}15`, color: riskColor, boxShadow: `inset 0 0 0 1px ${riskColor}30` }}>
                {safe(d.risk_level)} ({safe(d.risk_score)})
              </span>
            </Tooltip>
          )}
          {flameTpIds.map(tp => <FlameBadge key={tp} tpId={tp} />)}
          <button onClick={exportStix} className="flex items-center gap-1 rounded border border-border-subtle px-2 py-1 text-[10px] text-text-muted hover:text-text-primary transition-colors" title="Export STIX 2.1 bundle">
            <Download className="h-3 w-3" /> STIX
          </button>
          <button onClick={() => {
            const other = prompt('Enter domain to compare with:');
            if (other?.trim()) navigate(`/compare/${domain}/${other.trim()}`);
          }} className="flex items-center gap-1 rounded border border-border-subtle px-2 py-1 text-[10px] text-text-muted hover:text-text-primary transition-colors" title="Compare with another domain">
            <ArrowLeftRight className="h-3 w-3" /> Compare
          </button>
        </div>
      </div>

      {/* Timeline */}
      <Section title="Timeline" icon={<Clock className="h-3.5 w-3.5 text-white/30" />} defaultOpen={false}>
        <DomainTimeline data={d} />
      </Section>

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
      <Section title="DNS Infrastructure" icon={<Server className="h-3.5 w-3.5 text-mx/50" />} accentColor="rgba(91,138,191,0.12)">
        {d.resolution_chain && (
          <p className="text-[10px] text-text-muted mb-2">
            {d.resolution_chain.mx_shared
              ? `MX Server IP (Shared — ${d.resolution_chain.mx_provider_label})`
              : 'MX Server IP (Dedicated)'}
          </p>
        )}
        {d.resolution_chain && (
          <div className="mb-3">
            <ResolutionChain chain={d.resolution_chain} />
          </div>
        )}
        {d.resolution_chain?.mx_shared && (
          <div className="mb-3">
            <SharedInfraBanner
              provider={d.resolution_chain.mx_provider}
              providerLabel={d.resolution_chain.mx_provider_label}
              providerCategory="email"
            />
          </div>
        )}
        {d.a_record_chain && (
          <>
            <p className="text-[10px] text-text-muted mb-2 mt-4">
              {d.a_record_chain.web_shared
                ? `Web Hosting IP (Shared — ${d.a_record_chain.web_provider_label})`
                : 'Web Hosting IP (Dedicated)'}
            </p>
            <div className="mb-3">
              <ResolutionChain chain={d.a_record_chain} />
            </div>
            {d.a_record_chain.web_shared && (
              <div className="mb-3">
                <SharedInfraBanner
                  provider={d.a_record_chain.web_provider}
                  providerLabel={d.a_record_chain.web_provider_label}
                  providerCategory="web_hosting"
                />
              </div>
            )}
          </>
        )}
        <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Primary MX" value={d.primary_mx} mono /><Field label="MX IP" value={d.mx_ip} mono />
          <Field label="A Record (Web IP)" value={d.a_record} mono />
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

      {/* Risk & Reputation */}
      {showRisk && (
        <Section title="Risk & Reputation" icon={<AlertTriangle className="h-3.5 w-3.5 text-amber-400/50" />} accentColor="rgba(245,158,11,0.12)">
          <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-3">
            <Field label="Risk Score" value={d.risk_score != null ? `${d.risk_score} (${d.risk_level})` : null} />
            <Field label="Risk Tags" value={d.risk_tags} /><Field label="RBL Hits" value={d.rbl_hits} /><Field label="OTX Risk" value={d.otx_risk} />
          </dl>
          {d.risk_signals && (
            <div className="mt-4 space-y-1.5">
              <div className="text-[10px] font-semibold uppercase tracking-widest text-text-muted mb-2">Signal Breakdown</div>
              {Object.entries(d.risk_signals).map(([key, val]) => (
                <div key={key} className="flex items-center gap-2">
                  <span className="w-24 text-[10px] text-text-muted truncate">{safe(key)}</span>
                  <div className="flex-1 h-1.5 rounded-full bg-white/5 overflow-hidden">
                    <div className="h-full rounded-full transition-all" style={{ width: `${Math.min(val, 100)}%`, background: val >= 75 ? '#ef4444' : val >= 50 ? '#f97316' : val >= 25 ? '#eab308' : '#22c55e' }} />
                  </div>
                  <span className="w-8 text-right font-mono text-[10px] text-text-muted">{safe(Math.round(val))}</span>
                </div>
              ))}
            </div>
          )}
        </Section>
      )}

      {/* Shodan Intelligence */}
      {showShodan && (
        <Section title="Shodan Intelligence" icon={<Radar className="h-3.5 w-3.5 text-[#5b8abf]/50" />} accentColor="rgba(91,138,191,0.12)">
          <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-3">
            <Field label="Open Ports" value={d.shodan_ports} mono />
            <Field label="Vulnerabilities" value={d.shodan_vulns} />
            <Field label="Operating System" value={d.shodan_os} />
            <Field label="Tags" value={d.shodan_tags} />
            <Field label="Hostnames" value={d.shodan_hostnames} mono />
          </dl>
        </Section>
      )}

      {/* VirusTotal */}
      {showVT && (
        <Section title="VirusTotal" icon={<Bug className="h-3.5 w-3.5 text-red-400/50" />} accentColor="rgba(239,68,68,0.12)">
          <div className="flex flex-wrap items-center gap-4">
            {d.vt_malicious_count != null && (
              <div className="flex flex-col items-center rounded-lg bg-red-500/8 border border-red-500/15 px-4 py-2">
                <span className="font-mono text-2xl font-bold text-red-400">{safe(d.vt_malicious_count)}</span>
                <span className="text-[10px] text-text-muted">Malicious</span>
              </div>
            )}
            {d.vt_undetected_count != null && (
              <div className="flex flex-col items-center rounded-lg bg-green-500/8 border border-green-500/15 px-4 py-2">
                <span className="font-mono text-2xl font-bold text-green-400">{safe(d.vt_undetected_count)}</span>
                <span className="text-[10px] text-text-muted">Undetected</span>
              </div>
            )}
          </div>
          <dl className="mt-3 grid gap-x-6 gap-y-3 sm:grid-cols-2">
            <Field label="Last Analysis" value={d.vt_last_analysis} />
          </dl>
        </Section>
      )}

      {/* PhishTank / URLhaus */}
      {showPhishTank && (
        <Section title="PhishTank / URLhaus" icon={<Shield className="h-3.5 w-3.5 text-orange-400/50" />} accentColor="rgba(249,115,22,0.12)">
          <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
            <Field label="PhishTank URL" value={d.phishtank_phishtank_url} mono />
            <Field label="URLhaus Threat" value={d.phishtank_urlhaus_threat} />
            <Field label="Matched" value={d.phishtank_phishtank_match} />
          </dl>
        </Section>
      )}

      {/* OpenClaw Shadow AI */}
      {showOpenClaw && (
        <Section title="OpenClaw — Shadow AI" icon={<Eye className="h-3.5 w-3.5 text-purple-400/50" />} accentColor="rgba(168,85,247,0.12)">
          <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-3">
            <Field label="Agent Type" value={d.openclaw_agent_type} />
            <Field label="Exposure Level" value={d.openclaw_exposure_level} />
            <Field label="Model ID" value={d.openclaw_model_id} mono />
          </dl>
        </Section>
      )}

      {/* Related Domains */}
      {relatedDomains.length > 0 && (
        <Section title={`Related Domains (${relatedDomains.length})`} icon={<Users className="h-3.5 w-3.5 text-cyan-400/50" />} accentColor="rgba(6,182,212,0.12)" defaultOpen={false}>
          <div className="space-y-1">
            {relatedDomains.map(rd => (
              <Link key={rd.domain} to={`/investigate/${rd.domain}`}
                className="flex items-center gap-2 rounded px-2 py-1.5 text-xs hover:bg-white/[0.03] transition-colors"
              >
                <ExternalLink className="h-3 w-3 text-text-muted shrink-0" />
                <span className="font-mono text-text-secondary">{safe(rd.domain)}</span>
                <span className="ml-auto flex gap-1">
                  {rd.linkTypes.map(t => (
                    <span key={t} className="rounded bg-white/5 px-1.5 py-0.5 text-[9px] text-text-muted">{safe(t.replace('_', ' '))}</span>
                  ))}
                </span>
              </Link>
            ))}
          </div>
        </Section>
      )}

      {/* Visual Fingerprint */}
      {d.visual_cluster_id && (
        <Section title="Visual Fingerprint" icon={<Image className="h-3.5 w-3.5 text-indigo-400/50" />} accentColor="rgba(99,102,241,0.12)" defaultOpen={false}>
          <div className="flex gap-4">
            <img
              src={`./data/screenshots/${domain}.png`}
              alt={`Screenshot of ${domain}`}
              className="max-w-xs rounded-lg border border-border-subtle"
              onError={e => { e.target.style.display = 'none'; }}
            />
            <dl className="space-y-2">
              <Field label="Visual Cluster" value={d.visual_cluster_id} mono />
            </dl>
          </div>
        </Section>
      )}
    </div>
  );
}

function EntityCard({ title, titleColor, fields }) {
  const hasData = fields.some(f => f.value != null && f.value !== '' && f.value !== 'N/A');
  return (
    <div className="rounded-lg border border-border-subtle p-3.5" style={{ background: 'var(--bg-surface)' }}>
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
    <div className="rounded-lg border border-border-subtle p-3 hover:border-border-hover transition-colors" style={{ background: 'var(--bg-surface)' }}>
      <div className="flex flex-wrap items-center gap-2">
        <Tooltip text={`Fingerprint pattern match`}>
          <span className="rounded bg-orange-500/8 px-2 py-0.5 font-mono text-xs font-medium text-fp/80">{safe(m.fp_id)}</span>
        </Tooltip>
        <span className="text-xs text-text-secondary">{safe(m.fp_name)}</span>
        <ConfidenceBadge score={m.confidence} fpId={m.fp_id} />
        {evidence && (
          <button onClick={() => setExpanded(p => !p)} className="ml-auto text-[10px] text-text-muted hover:text-text-primary transition-colors">
            {expanded ? 'Hide ▲' : 'Evidence ▼'}
          </button>
        )}
      </div>
      {expanded && evidence && (
        <pre className="mt-2 max-h-48 overflow-auto rounded border border-border-subtle p-3 font-mono text-[10px] text-text-muted animate-slide-down" style={{ background: 'var(--bg-surface-raised)' }}>{evidence}</pre>
      )}
    </div>
  );
}
