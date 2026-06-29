import { useNavigate, Link } from 'react-router-dom';
import { Search, Globe, Fingerprint, Network, TrendingUp, ChevronLeft, ChevronRight } from 'lucide-react';
import { useState, useMemo } from 'react';
import { useData } from '@/context/DataContext';
import Tooltip from '@/components/Tooltip';
import Sparkline from '@/components/Sparkline';
import InfraResults from '@/components/InfraResults';
import { kpiTooltips } from '@/data/fpRegistry';

const LETTERS = 'abcdefghijklmnopqrstuvwxyz'.split('');
const DIGITS = '0123456789'.split('');
const PAGE_SIZE = 50;

export default function InvestigateLanding() {
  const navigate = useNavigate();
  const { stats, shardManifest, loadShard, infraIndex, history } = useData();
  const [query, setQuery] = useState('');
  const [pivotResults, setPivotResults] = useState(null);
  const [pivotLabel, setPivotLabel] = useState('');
  const [infraMeta, setInfraMeta] = useState(null);

  // Browse state
  const [activeShard, setActiveShard] = useState(null);
  const [shardData, setShardData] = useState(null);
  const [shardLoading, setShardLoading] = useState(false);
  const [page, setPage] = useState(0);
  const [sortKey, setSortKey] = useState('domain');
  const [sortAsc, setSortAsc] = useState(true);

  /** Extract domain list from an infra_index entry (handles both enriched and legacy formats) */
  function getEntryDomains(entry) {
    if (!entry) return [];
    if (Array.isArray(entry)) return entry; // legacy format: plain array
    return entry.domains || []; // enriched format: { domains, private, entity_stats }
  }

  function handleSubmit(e) {
    e.preventDefault();
    const q = query.trim();
    if (!q) return;

    // Clear previous infra metadata
    setInfraMeta(null);

    // Pivot search: ASN:, MX:, REG:, FP:
    const pivotMatch = q.match(/^(ASN|MX|REG|FP):\s*(.+)$/i);
    if (pivotMatch && infraIndex) {
      const type = pivotMatch[1].toUpperCase();
      const val = pivotMatch[2].trim();
      let results = [];
      let label = '';
      let matchedMeta = null;

      if (type === 'ASN' && infraIndex.asn) {
        const entry = infraIndex.asn[val];
        results = getEntryDomains(entry);
        label = `ASN ${val}`;
        if (entry && !Array.isArray(entry)) matchedMeta = { type: 'asn', key: val, ...entry };
      } else if (type === 'MX' && infraIndex.mx) {
        const lower = val.toLowerCase();
        for (const [k, entry] of Object.entries(infraIndex.mx)) {
          if (k.toLowerCase().includes(lower)) {
            results = [...results, ...getEntryDomains(entry)];
            label = `MX matching "${val}"`;
            if (!Array.isArray(entry)) matchedMeta = { type: 'mx', key: k, ...entry };
          }
        }
      } else if (type === 'REG' && infraIndex.registrar) {
        const lower = val.toLowerCase();
        for (const [k, entry] of Object.entries(infraIndex.registrar)) {
          if (k.toLowerCase().includes(lower)) {
            results = [...results, ...getEntryDomains(entry)];
            label = `Registrar matching "${val}"`;
            if (!Array.isArray(entry)) matchedMeta = { type: 'registrar', key: k, ...entry };
          }
        }
      } else if (type === 'FP' && infraIndex.fp) {
        const entry = infraIndex.fp[val] || infraIndex.fp[val.toUpperCase()];
        results = getEntryDomains(entry);
        label = `Fingerprint ${val}`;
        if (entry && !Array.isArray(entry)) matchedMeta = { type: 'fp', key: val.toUpperCase(), ...entry };
      }

      results = [...new Set(results)];
      setPivotResults(results);
      setPivotLabel(label || `${type}:${val}`);
      if (matchedMeta) setInfraMeta(matchedMeta);
      return;
    }

    // Auto-detection for unprefixed infrastructure inputs
    if (infraIndex) {
      const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(q);

      if (isIP) {
        // Search a_record index and MX index for IP matches
        let results = [];
        let matchedMeta = null;
        const aEntry = infraIndex.a_record?.[q];
        if (aEntry) {
          results.push(...getEntryDomains(aEntry));
          if (!Array.isArray(aEntry)) matchedMeta = { type: 'a_record', key: q, ...aEntry };
        }
        const mxEntry = infraIndex.mx?.[q];
        if (mxEntry) {
          results.push(...getEntryDomains(mxEntry));
          if (!Array.isArray(mxEntry)) matchedMeta = matchedMeta || { type: 'mx', key: q, ...mxEntry };
        }
        if (results.length > 0) {
          results = [...new Set(results)];
          setPivotResults(results);
          setPivotLabel(`IP ${q}`);
          if (matchedMeta) setInfraMeta(matchedMeta);
          return;
        }
      }

      // Check for exact MX key match
      if (infraIndex.mx?.[q]) {
        const entry = infraIndex.mx[q];
        const results = [...new Set(getEntryDomains(entry))];
        setPivotResults(results);
        setPivotLabel(`MX ${q}`);
        if (!Array.isArray(entry)) setInfraMeta({ type: 'mx', key: q, ...entry });
        return;
      }

      // Check for partial MX hostname match (contains dots, not an IP)
      if (q.includes('.') && !(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(q))) {
        const lower = q.toLowerCase();
        let results = [];
        let matchedMeta = null;
        for (const [k, entry] of Object.entries(infraIndex.mx || {})) {
          if (k.toLowerCase().includes(lower)) {
            results.push(...getEntryDomains(entry));
            if (!Array.isArray(entry)) matchedMeta = { type: 'mx', key: k, ...entry };
          }
        }
        if (results.length > 0) {
          results = [...new Set(results)];
          setPivotResults(results);
          setPivotLabel(`MX matching "${q}"`);
          if (matchedMeta) setInfraMeta(matchedMeta);
          return;
        }
      }
    }

    // Default: navigate to domain
    setPivotResults(null);
    navigate(`/investigate/${q}`);
  }

  async function selectShard(key) {
    if (key === activeShard) { setActiveShard(null); setShardData(null); return; }
    setActiveShard(key);
    setShardLoading(true);
    setPage(0);
    const data = await loadShard(key);
    setShardData(data);
    setShardLoading(false);
  }

  function toggleSort(key) {
    if (sortKey === key) setSortAsc(prev => !prev);
    else { setSortKey(key); setSortAsc(true); }
    setPage(0);
  }

  const rows = useMemo(() => {
    if (!shardData) return [];
    return Object.values(shardData).sort((a, b) => {
      const av = a[sortKey] ?? '';
      const bv = b[sortKey] ?? '';
      const cmp = String(av).localeCompare(String(bv), undefined, { numeric: true });
      return sortAsc ? cmp : -cmp;
    });
  }, [shardData, sortKey, sortAsc]);

  const pageCount = Math.ceil(rows.length / PAGE_SIZE);
  const pageRows = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const BROWSE_COLS = [
    { key: 'domain', label: 'Domain' },
    { key: 'primary_mx', label: 'MX' },
    { key: 'asn_name', label: 'ASN' },
    { key: 'cc', label: 'CC' },
    { key: 'http_status', label: 'HTTP' },
    { key: 'risk_tags', label: 'Risk' },
  ];

  const sparkData = useMemo(() => {
    if (!history || history.length < 2) return {};
    const last14 = history.slice(-14);
    return {
      total: last14.map(h => h.total || 0),
      live: last14.map(h => h.live || 0),
    };
  }, [history]);

  const statCards = [
    { icon: Globe, label: 'Domains Tracked', value: stats?.total_domains?.toLocaleString() ?? '—', tooltip: kpiTooltips.total_domains, spark: sparkData.total, sparkColor: '#888' },
    { icon: Fingerprint, label: 'FP Matches', value: stats?.matched_domains?.toLocaleString() ?? '—', tooltip: kpiTooltips.matched_domains },
    { icon: Network, label: 'Infra Clusters', value: stats?.total_clusters?.toLocaleString() ?? '—', tooltip: kpiTooltips.total_clusters },
    { icon: TrendingUp, label: 'Unique FPs', value: stats?.unique_fingerprints?.toLocaleString() ?? '—', tooltip: kpiTooltips.unique_fingerprints },
  ];

  return (
    <div className="space-y-8">
      {/* Hero */}
      <div className="flex flex-col items-center pt-10 pb-4">
        <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-xl" style={{ background: 'var(--nav-inactive-hover-bg)' }}>
          <Search className="h-6 w-6" style={{ color: 'var(--text-muted)' }} strokeWidth={1.5} />
        </div>
        <h1 className="mb-1 text-2xl font-normal tracking-tight" style={{ color: 'var(--text-primary)' }}>Domain Investigation</h1>
        <p className="mb-6 max-w-md text-center text-xs text-text-muted">
          Search any domain, IP address, or MX hostname. Use <span className="font-mono text-text-secondary">ASN:</span> <span className="font-mono text-text-secondary">MX:</span> <span className="font-mono text-text-secondary">REG:</span> <span className="font-mono text-text-secondary">FP:</span> prefixes for specific pivot types.
        </p>
        <form onSubmit={handleSubmit} className="relative w-full max-w-lg">
          <Search className="absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
          <input type="text" value={query} onChange={e => setQuery(e.target.value)}
            placeholder="Enter a domain to investigate…" autoFocus
            className="w-full rounded-lg border py-3 pl-10 pr-4 text-sm outline-none transition-colors"
            style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }}
          />
          <span className="absolute right-3.5 top-1/2 -translate-y-1/2 rounded border border-border-subtle px-1.5 py-0.5 text-[9px] text-text-muted">
            ↵
          </span>
        </form>
      </div>

      {/* Stats */}
      <div className="grid w-full grid-cols-2 gap-3 sm:grid-cols-4">
        {statCards.map(({ icon: Icon, label, value, tooltip, spark, sparkColor }) => (
          <Tooltip key={label} text={tooltip}>
            <div className="kpi-card w-full">
              <div className="flex items-center justify-between">
                <div>
                  <Icon className="mb-1.5 h-4 w-4 text-white/20" />
                  <div className="text-lg font-bold text-text-primary">{value}</div>
                  <div className="text-[10px] text-text-muted">{label}</div>
                </div>
                {spark && spark.length >= 2 && (
                  <Sparkline data={spark} color={sparkColor || '#888'} width={72} height={28} />
                )}
              </div>
            </div>
          </Tooltip>
        ))}
      </div>

      {/* Pivot Search Results */}
      {pivotResults && (
        <div className="animate-fade-in">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-xs text-text-muted">
              <span className="font-mono font-semibold text-text-secondary">{pivotResults.length.toLocaleString()}</span> domains for {pivotLabel}
            </span>
            <button onClick={() => { setPivotResults(null); setInfraMeta(null); }} className="text-[10px] text-text-muted hover:text-text-primary transition-colors">Clear ✕</button>
          </div>
          {pivotResults.length === 0 ? (
            <div className="glass-card p-6 text-center text-xs text-text-muted">No domains found</div>
          ) : infraMeta ? (
            <InfraResults infraMeta={infraMeta} pivotResults={pivotResults} />
          ) : (
            <div className="overflow-x-auto rounded-lg border border-border-subtle" style={{ background: 'var(--bg-surface)' }}>
              <table className="intel-table w-full text-left">
                <thead><tr><th>Domain</th></tr></thead>
                <tbody>
                  {pivotResults.slice(0, 200).map(d => (
                    <tr key={d} onClick={() => navigate(`/investigate/${d}`)}>
                      <td><span className="font-mono text-sm text-text-primary">{d}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Browse Section */}
      <div>
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-widest text-text-muted">Browse by Letter</h2>

        {/* Letter buttons */}
        <div className="flex flex-wrap gap-1 mb-1">
          {LETTERS.map(l => {
            const count = shardManifest?.[l]?.count;
            const isActive = activeShard === l;
            return (
              <button key={l} onClick={() => selectShard(l)}
                className={`flex flex-col items-center rounded-md px-2 py-1.5 text-xs font-mono transition-all ${isActive ? 'bg-white/10 text-white border border-white/15' : 'text-text-muted hover:bg-white/[0.03] hover:text-text-secondary border border-transparent'
                  }`}
              >
                <span className="font-semibold uppercase">{l}</span>
                {count != null && <span className="text-[8px] text-text-muted">{count > 1000 ? `${(count / 1000).toFixed(0)}k` : count}</span>}
              </button>
            );
          })}
        </div>
        <div className="flex flex-wrap gap-1 mb-4">
          {DIGITS.map(d => {
            const count = shardManifest?.[d]?.count;
            const isActive = activeShard === d;
            return (
              <button key={d} onClick={() => selectShard(d)}
                className={`flex flex-col items-center rounded-md px-2 py-1.5 text-xs font-mono transition-all ${isActive ? 'bg-white/10 text-white border border-white/15' : 'text-text-muted hover:bg-white/[0.03] hover:text-text-secondary border border-transparent'
                  }`}
              >
                <span className="font-semibold">{d}</span>
                {count != null && <span className="text-[8px] text-text-muted">{count > 1000 ? `${(count / 1000).toFixed(0)}k` : count}</span>}
              </button>
            );
          })}
        </div>

        {/* Shard table */}
        {activeShard && (
          <div className="animate-fade-in">
            {shardLoading ? (
              <div className="flex h-32 items-center justify-center">
                <div className="h-6 w-6 animate-spin rounded-full border-2 border-white/10 border-t-white/50" />
              </div>
            ) : (
              <>
                <div className="mb-2 flex items-center justify-between">
                  <span className="text-xs text-text-muted">
                    <span className="font-mono font-semibold text-text-secondary">{rows.length.toLocaleString()}</span> domains starting with "{activeShard.toUpperCase()}"
                  </span>
                  {pageCount > 1 && (
                    <span className="text-[10px] text-text-muted font-mono">
                      Page {page + 1} / {pageCount}
                    </span>
                  )}
                </div>

                <div className="overflow-x-auto rounded-lg border border-border-subtle" style={{ background: 'var(--bg-surface)' }}>
                  <table className="intel-table w-full text-left">
                    <thead>
                      <tr>
                        {BROWSE_COLS.map(col => (
                          <th key={col.key} className="cursor-pointer select-none" onClick={() => toggleSort(col.key)}>
                            {col.label}
                            {sortKey === col.key && (sortAsc ? ' ↑' : ' ↓')}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {pageRows.map(row => (
                        <tr key={row.domain} onClick={() => navigate(`/investigate/${row.domain}`)}>
                          <td><span className="font-mono text-sm text-text-primary">{row.domain}</span></td>
                          <td><span className="font-mono text-xs text-text-muted truncate max-w-[120px] block">{row.primary_mx || '—'}</span></td>
                          <td><span className="text-xs text-text-muted truncate max-w-[140px] block">{row.asn_name || row.asn || '—'}</span></td>
                          <td><span className="text-xs text-text-muted">{row.cc || '—'}</span></td>
                          <td><span className="font-mono text-xs text-text-muted">{row.http_status || '—'}</span></td>
                          <td>
                            {row.risk_tags ? (
                              <span className="rounded bg-red-500/10 px-1.5 py-0.5 text-[10px] text-red-400/80">{row.risk_tags}</span>
                            ) : <span className="text-text-muted text-xs">—</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {pageCount > 1 && (
                  <div className="mt-2 flex justify-end gap-1.5">
                    <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
                      className="flex items-center gap-1 rounded-md border border-border-subtle px-2.5 py-1 text-xs text-text-muted hover:text-text-primary disabled:opacity-20 transition-colors"
                    ><ChevronLeft className="h-3 w-3" /> Prev</button>
                    <button onClick={() => setPage(p => Math.min(pageCount - 1, p + 1))} disabled={page >= pageCount - 1}
                      className="flex items-center gap-1 rounded-md border border-border-subtle px-2.5 py-1 text-xs text-text-muted hover:text-text-primary disabled:opacity-20 transition-colors"
                    >Next <ChevronRight className="h-3 w-3" /></button>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
