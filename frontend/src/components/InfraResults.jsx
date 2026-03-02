import { useState, useMemo, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useData } from '@/context/DataContext';
import {
  Server, Network, Globe, ExternalLink, ChevronLeft, ChevronRight,
  Lock, Users, ShieldAlert, Mail, Hash, Wifi,
} from 'lucide-react';

const PAGE_SIZE = 50;

/** Map infra type to display label and icon */
function infraLabel(type) {
  switch (type) {
    case 'mx': return { label: 'MX Host', Icon: Mail };
    case 'asn': return { label: 'ASN', Icon: Network };
    case 'a_record': return { label: 'IP Address', Icon: Wifi };
    case 'ip': return { label: 'IP Address', Icon: Wifi };
    case 'registrar': return { label: 'Registrar', Icon: Globe };
    case 'fp': return { label: 'Fingerprint', Icon: Hash };
    default: return { label: type?.toUpperCase() || 'Infrastructure', Icon: Server };
  }
}

/** Determine the correct external investigation URL for OTX */
function otxUrl(type, key) {
  const isIPv4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(key);
  if (isIPv4) return `https://otx.alienvault.com/indicator/ip/${key}`;
  return `https://otx.alienvault.com/indicator/hostname/${key}`;
}

/** Determine the correct external investigation URL for Silent Push */
function silentPushUrl(type, key) {
  const isIPv4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(key);
  if (isIPv4) return `https://explore.silentpush.com/enrichment/ipv4/${key}`;
  return `https://explore.silentpush.com/enrichment/domain/${key}`;
}

/** Determine shard key for a domain */
function shardKeyFor(domain) {
  if (!domain) return 'misc';
  const first = domain[0].toLowerCase();
  if (/[a-z]/.test(first)) return first;
  if (/[0-9]/.test(first)) return first;
  return 'misc';
}

const COLUMNS = [
  { key: 'domain', label: 'Domain' },
  { key: 'registrant', label: 'Registrant' },
  { key: 'os_score', label: 'OS Score' },
  { key: 'icij_match', label: 'ICIJ' },
  { key: 'gleif_status', label: 'GLEIF' },
  { key: 'risk_score', label: 'Risk Score' },
];

export default function InfraResults({ infraMeta, pivotResults }) {
  const { loadShard } = useData();
  const [domainData, setDomainData] = useState({});
  const [loadingData, setLoadingData] = useState(true);
  const [page, setPage] = useState(0);
  const [sortKey, setSortKey] = useState('domain');
  const [sortAsc, setSortAsc] = useState(true);

  // Load domain data for all pivot results by fetching required shards
  useEffect(() => {
    let cancelled = false;
    async function loadAllDomainData() {
      if (!pivotResults || pivotResults.length === 0) {
        setDomainData({});
        setLoadingData(false);
        return;
      }
      setLoadingData(true);
      // Group domains by shard key
      const shardKeys = new Set(pivotResults.map(shardKeyFor));
      const shardResults = {};
      await Promise.all(
        [...shardKeys].map(async (key) => {
          const data = await loadShard(key);
          if (!cancelled) Object.assign(shardResults, data);
        })
      );
      if (!cancelled) {
        setDomainData(shardResults);
        setLoadingData(false);
      }
    }
    loadAllDomainData();
    return () => { cancelled = true; };
  }, [pivotResults, loadShard]);

  const { label: typeLabel, Icon: TypeIcon } = infraLabel(infraMeta?.type);

  // Build enriched row data from pivot results + loaded domain data
  const rows = useMemo(() => {
    if (!pivotResults) return [];
    return pivotResults.map(domainName => {
      const d = domainData[domainName] || null;
      return {
        domain: domainName,
        registrant: d?.whois_registrar || d?.registrant_org || null,
        os_score: d?.os_match_score != null ? Number(d.os_match_score) : null,
        icij_match: d?.icij_entity_match || null,
        gleif_status: d?.gleif_status || null,
        risk_score: d?.risk_score != null ? Number(d.risk_score) : null,
      };
    });
  }, [pivotResults, domainData]);

  // Sorted rows
  const sortedRows = useMemo(() => {
    return [...rows].sort((a, b) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      // Nulls sort last
      if (av == null && bv == null) return 0;
      if (av == null) return 1;
      if (bv == null) return -1;
      const cmp = typeof av === 'number' && typeof bv === 'number'
        ? av - bv
        : String(av).localeCompare(String(bv), undefined, { numeric: true });
      return sortAsc ? cmp : -cmp;
    });
  }, [rows, sortKey, sortAsc]);

  const pageCount = Math.ceil(sortedRows.length / PAGE_SIZE);
  const pageRows = sortedRows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const toggleSort = useCallback((key) => {
    setSortKey(prev => {
      if (prev === key) {
        setSortAsc(a => !a);
        return key;
      }
      setSortAsc(true);
      return key;
    });
    setPage(0);
  }, []);

  // Entity screening summary
  const entitySummary = useMemo(() => {
    if (!infraMeta?.entity_stats) return null;
    const { os_hits = 0, icij_hits = 0, gleif_active = 0, total = 0 } = infraMeta.entity_stats;
    // Approximate unique domains with hits (may overlap, but we use the raw counts for display)
    const totalHits = os_hits + icij_hits + gleif_active;
    if (totalHits === 0) return null;
    return { os_hits, icij_hits, gleif_active, totalHits, total };
  }, [infraMeta]);

  const isPrivate = infraMeta?.private === true;

  return (
    <div className="animate-fade-in space-y-4">
      {/* (a) Infrastructure Header */}
      <div
        className="rounded-lg border p-5"
        style={{
          background: 'var(--bg-surface)',
          borderColor: 'var(--border-subtle)',
        }}
      >
        <div className="flex flex-wrap items-center gap-3">
          <TypeIcon className="h-5 w-5" style={{ color: 'var(--text-muted)' }} />
          <span
            className="text-xs font-semibold uppercase tracking-wider"
            style={{ color: 'var(--text-muted)' }}
          >
            {typeLabel}
          </span>
          <span
            className="font-mono text-lg font-bold"
            style={{ color: 'var(--text-primary)' }}
          >
            {infraMeta?.key || '—'}
          </span>

          {/* Private / Shared badge */}
          {isPrivate ? (
            <span
              className="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold"
              style={{
                background: 'rgba(192, 39, 45, 0.12)',
                color: '#C0272D',
                boxShadow: 'inset 0 0 0 1px rgba(192, 39, 45, 0.25)',
              }}
            >
              <Lock className="h-3 w-3" />
              Private
            </span>
          ) : (
            <span
              className="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold"
              style={{
                background: 'var(--bg-elevated)',
                color: 'var(--text-muted)',
                boxShadow: 'inset 0 0 0 1px var(--border-subtle)',
              }}
            >
              <Users className="h-3 w-3" />
              Shared
            </span>
          )}

          {/* Cluster size */}
          <span
            className="rounded-full px-2.5 py-0.5 text-xs font-mono font-semibold"
            style={{
              background: 'var(--bg-elevated)',
              color: 'var(--text-secondary)',
              boxShadow: 'inset 0 0 0 1px var(--border-subtle)',
            }}
          >
            {pivotResults?.length?.toLocaleString() || 0} domains
          </span>
        </div>
      </div>

      {/* (b) Entity Screening Summary Banner */}
      {entitySummary && (
        <div
          className="rounded-lg border p-4"
          style={{
            background: 'rgba(192, 39, 45, 0.04)',
            borderColor: 'rgba(192, 39, 45, 0.15)',
          }}
        >
          <div className="flex items-start gap-2.5">
            <ShieldAlert
              className="mt-0.5 h-4 w-4 shrink-0"
              style={{ color: '#C0272D' }}
            />
            <div className="space-y-1.5">
              <p className="text-sm" style={{ color: 'var(--text-primary)' }}>
                <span className="font-semibold" style={{ color: '#C0272D' }}>
                  {entitySummary.totalHits}
                </span>{' '}
                entity screening hits across{' '}
                <span className="font-semibold" style={{ color: 'var(--text-secondary)' }}>
                  {entitySummary.total}
                </span>{' '}
                domains
              </p>
              <div className="flex flex-wrap gap-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                {entitySummary.os_hits > 0 && (
                  <span>
                    <span className="font-mono font-semibold" style={{ color: '#ef4444' }}>
                      {entitySummary.os_hits}
                    </span>{' '}
                    OpenSanctions
                  </span>
                )}
                {entitySummary.icij_hits > 0 && (
                  <span>
                    <span className="font-mono font-semibold" style={{ color: '#eab308' }}>
                      {entitySummary.icij_hits}
                    </span>{' '}
                    ICIJ
                  </span>
                )}
                {entitySummary.gleif_active > 0 && (
                  <span>
                    <span className="font-mono font-semibold" style={{ color: '#22c55e' }}>
                      {entitySummary.gleif_active}
                    </span>{' '}
                    GLEIF Active
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* (c) External Investigation Buttons */}
      {infraMeta?.key && (
        <div className="flex flex-wrap gap-2">
          <a
            href={otxUrl(infraMeta.type, infraMeta.key)}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-medium transition-colors hover:bg-white/[0.03]"
            style={{
              borderColor: 'var(--border-subtle)',
              color: 'var(--text-secondary)',
              background: 'transparent',
            }}
          >
            <ExternalLink className="h-3.5 w-3.5" />
            Search in OTX
          </a>
          <a
            href={silentPushUrl(infraMeta.type, infraMeta.key)}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-medium transition-colors hover:bg-white/[0.03]"
            style={{
              borderColor: 'var(--border-subtle)',
              color: 'var(--text-secondary)',
              background: 'transparent',
            }}
          >
            <ExternalLink className="h-3.5 w-3.5" />
            Search in Silent Push
          </a>
        </div>
      )}

      {/* (d) Domain Table */}
      {loadingData ? (
        <div className="flex h-32 items-center justify-center">
          <div className="flex flex-col items-center gap-3">
            <div className="h-6 w-6 animate-spin rounded-full border-2 border-white/10 border-t-white/50" />
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
              Loading domain data…
            </span>
          </div>
        </div>
      ) : (
        <>
          <div className="flex items-center justify-between">
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
              <span
                className="font-mono font-semibold"
                style={{ color: 'var(--text-secondary)' }}
              >
                {sortedRows.length.toLocaleString()}
              </span>{' '}
              domains
            </span>
            {pageCount > 1 && (
              <span className="font-mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
                Page {page + 1} / {pageCount}
              </span>
            )}
          </div>

          <div
            className="overflow-x-auto rounded-lg border"
            style={{
              background: 'var(--bg-surface)',
              borderColor: 'var(--border-subtle)',
            }}
          >
            <table className="intel-table w-full text-left">
              <thead>
                <tr>
                  {COLUMNS.map(col => (
                    <th
                      key={col.key}
                      className="cursor-pointer select-none"
                      onClick={() => toggleSort(col.key)}
                    >
                      {col.label}
                      {sortKey === col.key && (sortAsc ? ' \u2191' : ' \u2193')}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {pageRows.length === 0 ? (
                  <tr>
                    <td
                      colSpan={COLUMNS.length}
                      className="text-center text-xs py-8"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      No domains found
                    </td>
                  </tr>
                ) : (
                  pageRows.map(row => (
                    <tr key={row.domain}>
                      <td>
                        <Link
                          to={`/investigate/${row.domain}`}
                          className="font-mono text-sm hover:underline"
                          style={{ color: 'var(--text-primary)' }}
                        >
                          {row.domain}
                        </Link>
                      </td>
                      <td>
                        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                          {row.registrant || '\u2014'}
                        </span>
                      </td>
                      <td>
                        {row.os_score != null ? (
                          <span
                            className="font-mono text-xs font-semibold"
                            style={{ color: row.os_score > 0 ? '#ef4444' : 'var(--text-muted)' }}
                          >
                            {row.os_score}
                          </span>
                        ) : (
                          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            {'\u2014'}
                          </span>
                        )}
                      </td>
                      <td>
                        {row.icij_match ? (
                          <span
                            className="rounded px-1.5 py-0.5 text-[10px] font-medium"
                            style={{
                              background: 'rgba(234, 179, 8, 0.1)',
                              color: '#eab308',
                            }}
                          >
                            {row.icij_match}
                          </span>
                        ) : (
                          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            {'\u2014'}
                          </span>
                        )}
                      </td>
                      <td>
                        {row.gleif_status ? (
                          <span
                            className="rounded px-1.5 py-0.5 text-[10px] font-medium"
                            style={{
                              background:
                                row.gleif_status === 'ACTIVE'
                                  ? 'rgba(34, 197, 94, 0.1)'
                                  : 'rgba(255, 255, 255, 0.05)',
                              color:
                                row.gleif_status === 'ACTIVE'
                                  ? '#22c55e'
                                  : 'var(--text-muted)',
                            }}
                          >
                            {row.gleif_status}
                          </span>
                        ) : (
                          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            {'\u2014'}
                          </span>
                        )}
                      </td>
                      <td>
                        {row.risk_score != null ? (
                          <RiskBadge score={row.risk_score} />
                        ) : (
                          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            {'\u2014'}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {pageCount > 1 && (
            <div className="flex justify-end gap-1.5">
              <button
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
                className="flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs transition-colors disabled:opacity-20"
                style={{
                  borderColor: 'var(--border-subtle)',
                  color: 'var(--text-muted)',
                }}
              >
                <ChevronLeft className="h-3 w-3" /> Prev
              </button>
              <button
                onClick={() => setPage(p => Math.min(pageCount - 1, p + 1))}
                disabled={page >= pageCount - 1}
                className="flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs transition-colors disabled:opacity-20"
                style={{
                  borderColor: 'var(--border-subtle)',
                  color: 'var(--text-muted)',
                }}
              >
                Next <ChevronRight className="h-3 w-3" />
              </button>
            </div>
          )}
        </>
      )}

      {/* (e) Pipeline Hint */}
      <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
        To add these domains to the pipeline, add them to{' '}
        <span className="font-mono">manual_candidates.csv</span>
      </p>
    </div>
  );
}

/** Risk score badge with color coding */
function RiskBadge({ score }) {
  const num = Number(score);
  let color, bg;
  if (num >= 75) {
    color = '#ef4444';
    bg = 'rgba(239, 68, 68, 0.1)';
  } else if (num >= 50) {
    color = '#f97316';
    bg = 'rgba(249, 115, 22, 0.1)';
  } else if (num >= 25) {
    color = '#eab308';
    bg = 'rgba(234, 179, 8, 0.1)';
  } else {
    color = '#22c55e';
    bg = 'rgba(34, 197, 94, 0.1)';
  }
  return (
    <span
      className="rounded-full px-2 py-0.5 font-mono text-xs font-semibold"
      style={{ background: bg, color }}
    >
      {num}
    </span>
  );
}
