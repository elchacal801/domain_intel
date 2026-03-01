import { useState, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useData } from '@/context/DataContext';
import SigmaGraph from '@/components/SigmaGraph';
import ClusterConfidenceBadge from '@/components/ClusterConfidenceBadge';
import SharedInfraBanner from '@/components/SharedInfraBanner';
import { Network, Sliders, ExternalLink, BarChart3, ChevronLeft, ChevronRight, X, SlidersHorizontal } from 'lucide-react';

const TYPE_META = {
  mx_host: { label: 'MX Host', color: '#3b82f6' },
  ip: { label: 'MX Server IP', color: '#f97316' },
  registrar_ns: { label: 'Registrar+NS', color: '#22c55e' },
  a_record_ip: { label: 'Web Hosting IP', color: '#a855f7' },
};

const PAGE_SIZE = 30;

/** Extract top infrastructure nodes ranked by connected domain count. */
function buildClusterTable(data) {
  if (!data?.nodes?.length) return [];
  const nodeMap = new Map();
  for (const n of data.nodes) nodeMap.set(n.id, n);

  // Count domain neighbors per infra node
  const infraDomains = new Map();
  for (const edge of data.edges || []) {
    const src = nodeMap.get(edge.source);
    const tgt = nodeMap.get(edge.target);
    if (!src || !tgt) continue;
    if (src.type !== 'domain' && tgt.type === 'domain') {
      if (!infraDomains.has(edge.source)) infraDomains.set(edge.source, new Set());
      infraDomains.get(edge.source).add(tgt.label);
    }
    if (tgt.type !== 'domain' && src.type === 'domain') {
      if (!infraDomains.has(edge.target)) infraDomains.set(edge.target, new Set());
      infraDomains.get(edge.target).add(src.label);
    }
  }

  const rows = [];
  for (const [id, domains] of infraDomains) {
    const node = nodeMap.get(id);
    if (!node || domains.size < 3) continue;
    rows.push({
      id,
      label: node.label,
      type: node.type,
      domainCount: domains.size,
      domains: [...domains].sort(),
      shared_infra: node.shared_infra || false,
      provider: node.provider || null,
      provider_label: node.provider_label || null,
      provider_category: node.provider_category || null,
      confidence: node.confidence != null ? node.confidence : null,
      confidence_level: node.confidence_level || null,
      confidence_breakdown: node.confidence_breakdown || null,
      resolution_method: node.resolution_method || null,
      domain_count: node.domain_count || null,
      related_mx_hosts: node.related_mx_hosts || null,
      hosting_asn: node.hosting_asn || null,
      hosting_asn_name: node.hosting_asn_name || null,
    });
  }
  rows.sort((a, b) => b.domainCount - a.domainCount);
  return rows;
}

/** Build a subgraph for a single infra node + its neighbors. */
function buildSubgraph(data, infraId) {
  if (!data?.nodes?.length) return { nodes: [], edges: [] };
  const nodeMap = new Map();
  for (const n of data.nodes) nodeMap.set(n.id, n);

  const neighborIds = new Set();
  neighborIds.add(infraId);
  const subEdges = [];
  for (const edge of data.edges || []) {
    if (edge.source === infraId || edge.target === infraId) {
      neighborIds.add(edge.source);
      neighborIds.add(edge.target);
      subEdges.push(edge);
    }
  }

  const subNodes = [];
  for (const id of neighborIds) {
    const node = nodeMap.get(id);
    if (node) subNodes.push(node);
  }

  return { nodes: subNodes, edges: subEdges };
}

export default function ClusterView() {
  const { clusters, loading } = useData();
  const navigate = useNavigate();

  const [view, setView] = useState('table'); // 'table' | 'graph'
  const [selectedCluster, setSelectedCluster] = useState(null);
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [showSharedInfra, setShowSharedInfra] = useState(true);
  const [confidenceFilter, setConfidenceFilter] = useState('all');
  const [sortBy, setSortBy] = useState('size');

  // Wrappers that reset page when filter state changes
  const updateShowSharedInfra = useCallback((v) => { setShowSharedInfra(v); setPage(0); }, []);
  const updateConfidenceFilter = useCallback((v) => { setConfidenceFilter(v); setPage(0); }, []);
  const updateSortBy = useCallback((v) => { setSortBy(v); setPage(0); }, []);

  const clusterTable = useMemo(() => buildClusterTable(clusters), [clusters]);

  const sharedCount = useMemo(
    () => clusterTable.filter(r => r.shared_infra).length,
    [clusterTable],
  );

  const filtered = useMemo(() => {
    let result = clusterTable;

    // Text search (existing)
    if (search) {
      const l = search.toLowerCase();
      result = result.filter(r => r.label.toLowerCase().includes(l));
    }

    // Filter out shared infra when toggle is off
    if (!showSharedInfra) {
      result = result.filter(r => !r.shared_infra);
    }

    // Confidence level filter
    if (confidenceFilter !== 'all') {
      result = result.filter(r => r.confidence_level === confidenceFilter);
    }

    // Sort — shared infra always sinks to bottom, then by selected field
    if (sortBy === 'confidence') {
      result = [...result].sort((a, b) => {
        if (a.shared_infra !== b.shared_infra) return a.shared_infra ? 1 : -1;
        return (b.confidence || 0) - (a.confidence || 0);
      });
    } else {
      result = [...result].sort((a, b) => {
        if (a.shared_infra !== b.shared_infra) return a.shared_infra ? 1 : -1;
        return b.domainCount - a.domainCount;
      });
    }

    return result;
  }, [clusterTable, search, showSharedInfra, confidenceFilter, sortBy]);

  const pageCount = Math.ceil(filtered.length / PAGE_SIZE);
  const pageRows = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const subgraph = useMemo(() => {
    if (!selectedCluster || !clusters) return null;
    return buildSubgraph(clusters, selectedCluster.id);
  }, [selectedCluster, clusters]);

  const handleNodeClick = useCallback((info) => {
    if (!info) return;
    if (info.type === 'domain') navigate(`/investigate/${info.label}`);
  }, [navigate]);

  const graphFilters = useMemo(() => ({
    types: ['mx_host', 'ip', 'registrar_ns', 'a_record_ip'],
    minSize: 0,
  }), []);

  if (loading) {
    return (
      <div className="flex h-80 items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-7 w-7 animate-spin rounded-full border-2 border-white/10 border-t-white/50" />
          <span className="text-xs text-text-muted">Loading clusters...</span>
        </div>
      </div>
    );
  }

  if (clusterTable.length === 0) {
    return (
      <div className="flex h-80 flex-col items-center justify-center gap-3">
        <Network className="h-8 w-8 text-white/10" />
        <p className="text-sm text-text-muted">No cluster data available.</p>
      </div>
    );
  }

  /** Render the type label, appending "(Shared)" for shared infra IP nodes. */
  const renderTypeLabel = (row) => {
    const meta = TYPE_META[row.type];
    const label = meta?.label || row.type;
    if (row.shared_infra && row.type === 'ip') return `${label} (Shared)`;
    return label;
  };

  const CONFIDENCE_LEVELS = ['all', 'high', 'medium', 'low'];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-text-primary">Infrastructure Clusters</h1>
          <p className="text-xs text-text-muted">
            {clusterTable.length.toLocaleString()} clusters{sharedCount > 0 && ` (${sharedCount} shared infrastructure)`} linking {clusters?.nodes?.length?.toLocaleString() || 0} nodes
          </p>
        </div>
        <div className="flex gap-1">
          <button onClick={() => { setView('table'); setSelectedCluster(null); }}
            className={`rounded-md px-3 py-1.5 text-xs font-medium transition-all ${view === 'table' ? 'bg-white/8 text-white border border-white/10' : 'text-text-muted hover:text-text-secondary border border-transparent'}`}
          ><BarChart3 className="inline h-3 w-3 mr-1" />Table</button>
          <button onClick={() => setView('graph')}
            className={`rounded-md px-3 py-1.5 text-xs font-medium transition-all ${view === 'graph' ? 'bg-white/8 text-white border border-white/10' : 'text-text-muted hover:text-text-secondary border border-transparent'}`}
          ><Network className="inline h-3 w-3 mr-1" />Graph</button>
        </div>
      </div>

      {view === 'table' && (
        <>
          {/* Search */}
          <div className="glass-card p-2.5">
            <input type="text" placeholder="Search clusters by MX, IP, or registrar..." value={search}
              onChange={e => { setSearch(e.target.value); setPage(0); }}
              className="w-full rounded-md border border-border-subtle py-1.5 px-3 text-xs text-text-primary placeholder-text-muted outline-none focus:border-white/15 transition-colors"
              style={{ background: 'var(--bg-surface-input)' }}
            />
          </div>

          {/* Filter controls */}
          <div className="flex flex-wrap items-center gap-4 rounded-lg border border-border-subtle px-3 py-2" style={{ background: 'var(--bg-surface)' }}>
            <div className="flex items-center gap-1.5 text-xs text-text-muted">
              <SlidersHorizontal className="h-3 w-3" />
              <span>Filters</span>
            </div>

            {/* Shared infra toggle */}
            <label className="flex items-center gap-1.5 text-xs text-text-secondary cursor-pointer select-none">
              <input
                type="checkbox"
                checked={showSharedInfra}
                onChange={e => updateShowSharedInfra(e.target.checked)}
                className="rounded border border-border-subtle"
              />
              Show shared infrastructure
            </label>

            {/* Confidence filter */}
            <div className="flex items-center gap-1">
              {CONFIDENCE_LEVELS.map(level => (
                <button
                  key={level}
                  onClick={() => updateConfidenceFilter(level)}
                  className={`rounded-md border px-2 py-0.5 text-xs font-medium transition-colors ${
                    confidenceFilter === level
                      ? 'border-white/10 bg-white/8 text-white'
                      : 'border-border-subtle text-text-muted hover:text-text-secondary'
                  }`}
                >
                  {level.charAt(0).toUpperCase() + level.slice(1)}
                </button>
              ))}
            </div>

            {/* Sort control */}
            <div className="flex items-center gap-1.5 ml-auto">
              <span className="text-xs text-text-muted">Sort:</span>
              <select
                value={sortBy}
                onChange={e => updateSortBy(e.target.value)}
                className="rounded-md border border-border-subtle py-0.5 px-2 text-xs text-text-secondary outline-none transition-colors focus:border-white/15"
                style={{ background: 'var(--bg-surface-input)' }}
              >
                <option value="size">Size</option>
                <option value="confidence">Confidence</option>
              </select>
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto rounded-lg border border-border-subtle" style={{ background: 'var(--bg-surface)' }}>
            <table className="intel-table w-full text-left">
              <thead>
                <tr>
                  <th>Infrastructure Node</th>
                  <th>Type</th>
                  <th>Confidence</th>
                  <th>Provider</th>
                  <th className="text-right">Connected Domains</th>
                  <th>Top Connected</th>
                </tr>
              </thead>
              <tbody>
                {pageRows.map(row => (
                  <tr
                    key={row.id}
                    onClick={() => { setSelectedCluster(row); setView('graph'); }}
                    className={row.shared_infra ? 'opacity-60' : ''}
                  >
                    <td><span className="font-mono text-sm text-text-primary">{row.label}</span></td>
                    <td>
                      <span className="inline-flex items-center gap-1.5 text-xs text-text-muted">
                        <span className="h-2 w-2 rounded-full" style={{ backgroundColor: TYPE_META[row.type]?.color || '#888' }} />
                        {renderTypeLabel(row)}
                      </span>
                    </td>
                    <td>
                      <ClusterConfidenceBadge confidence={row.confidence} confidenceLevel={row.confidence_level} />
                    </td>
                    <td>
                      {row.shared_infra && row.provider_label ? (
                        <span className="text-xs text-text-secondary">{row.provider_label}</span>
                      ) : (
                        <span className="text-xs text-text-muted">&mdash;</span>
                      )}
                    </td>
                    <td className="text-right font-mono text-sm text-text-primary">{row.domainCount.toLocaleString()}</td>
                    <td>
                      <span className="text-xs text-text-muted">
                        {row.domains.slice(0, 3).join(', ')}
                        {row.domains.length > 3 && ` +${row.domains.length - 3}`}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {pageCount > 1 && (
            <div className="flex items-center justify-between text-xs">
              <span className="font-mono text-text-muted">
                {filtered.length.toLocaleString()} clusters
              </span>
              <div className="flex gap-1.5">
                <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
                  className="flex items-center gap-1 rounded-md border border-border-subtle px-2.5 py-1 text-text-muted hover:text-text-primary disabled:opacity-20 transition-colors"
                ><ChevronLeft className="h-3 w-3" /> Prev</button>
                <button onClick={() => setPage(p => Math.min(pageCount - 1, p + 1))} disabled={page >= pageCount - 1}
                  className="flex items-center gap-1 rounded-md border border-border-subtle px-2.5 py-1 text-text-muted hover:text-text-primary disabled:opacity-20 transition-colors"
                >Next <ChevronRight className="h-3 w-3" /></button>
              </div>
            </div>
          )}
        </>
      )}

      {view === 'graph' && (
        <div className="flex h-[calc(100vh-10rem)] gap-4 animate-fade-in">
          <div className="relative flex-1 overflow-hidden rounded-lg border border-border-subtle" style={{ background: 'var(--bg-body)' }}>
            {/* Back to table */}
            <button onClick={() => { setView('table'); setSelectedCluster(null); }}
              className="absolute left-3 top-3 z-10 flex items-center gap-1 rounded-md border border-border-subtle px-2.5 py-1 text-xs text-text-secondary hover:text-text-primary transition-colors"
              style={{ background: 'var(--bg-surface-raised)' }}
            ><ChevronLeft className="h-3 w-3" /> Back to table</button>

            {selectedCluster && (
              <div className="absolute right-3 top-3 z-10 rounded-md border border-border-subtle px-3 py-1.5 text-xs text-text-secondary" style={{ background: 'var(--bg-surface-raised)' }}>
                <span className="font-mono text-text-primary">{selectedCluster.label}</span>
                <span className="text-text-muted ml-2">{selectedCluster.domainCount} domains</span>
              </div>
            )}

            {subgraph ? (
              <SigmaGraph data={subgraph} onClickNode={handleNodeClick} filters={graphFilters} />
            ) : (
              <div className="flex h-full items-center justify-center text-xs text-text-muted">
                Select a cluster from the table to visualize
              </div>
            )}
          </div>

          {/* Sidebar */}
          {selectedCluster && (
            <div className="w-72 shrink-0 overflow-y-auto rounded-lg border border-border-subtle p-4" style={{ background: 'var(--bg-surface)' }}>
              <div className="mb-4">
                <div className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">
                  {TYPE_META[selectedCluster.type]?.label}
                </div>
                <div className="mt-1 break-all font-mono text-base font-bold text-text-primary">{selectedCluster.label}</div>
                <div className="mt-1 text-xs text-text-muted">{selectedCluster.domainCount} connected domains</div>
              </div>

              {/* Confidence section */}
              {selectedCluster.confidence != null && (
                <>
                  <div className="h-px bg-border-subtle mb-3" />
                  <div className="text-[10px] font-semibold uppercase tracking-widest text-text-muted mb-2">Confidence</div>
                  <div className="mb-2">
                    <ClusterConfidenceBadge confidence={selectedCluster.confidence} confidenceLevel={selectedCluster.confidence_level} />
                  </div>
                  {selectedCluster.confidence_breakdown && (
                    <div className="space-y-0.5 mb-3">
                      {Object.entries(selectedCluster.confidence_breakdown).map(([key, value]) => (
                        <div key={key} className="flex items-center justify-between text-xs">
                          <span className="text-text-muted">{key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</span>
                          <span className={`font-mono ${value >= 0 ? 'text-text-secondary' : 'text-red-400'}`}>
                            {value > 0 ? `+${value}` : value}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}

              {/* Shared infra / provider info */}
              {selectedCluster.shared_infra && (
                <>
                  <div className="h-px bg-border-subtle mb-3" />
                  <div className="mb-3">
                    <SharedInfraBanner
                      provider={selectedCluster.provider}
                      providerLabel={selectedCluster.provider_label}
                      providerCategory={selectedCluster.provider_category}
                    />
                  </div>
                </>
              )}

              {/* Resolution method */}
              {selectedCluster.resolution_method && (
                <>
                  <div className="h-px bg-border-subtle mb-3" />
                  <div className="text-[10px] font-semibold uppercase tracking-widest text-text-muted mb-1">Resolution Method</div>
                  <div className="text-xs font-mono text-text-secondary mb-3">{selectedCluster.resolution_method}</div>
                </>
              )}

              {/* Related MX hosts */}
              {selectedCluster.related_mx_hosts && selectedCluster.related_mx_hosts.length > 0 && (
                <>
                  <div className="h-px bg-border-subtle mb-3" />
                  <div className="text-[10px] font-semibold uppercase tracking-widest text-text-muted mb-2">Related MX Hosts</div>
                  <div className="space-y-0.5 mb-3">
                    {selectedCluster.related_mx_hosts.map(host => (
                      <div key={host} className="text-xs font-mono text-text-secondary px-2 py-1 rounded bg-white/[0.02]">
                        {host}
                      </div>
                    ))}
                  </div>
                </>
              )}

              {/* Hosting ASN */}
              {selectedCluster.type === 'a_record_ip' && selectedCluster.hosting_asn && (
                <>
                  <div className="h-px bg-border-subtle mb-3" />
                  <div className="text-[10px] font-semibold uppercase tracking-widest text-text-muted mb-2">
                    Hosting ASN
                  </div>
                  <div className="text-xs font-mono text-text-secondary px-2 py-1 rounded bg-white/[0.02]">
                    AS{selectedCluster.hosting_asn}
                    {selectedCluster.hosting_asn_name && ` (${selectedCluster.hosting_asn_name})`}
                  </div>
                </>
              )}

              <div className="h-px bg-border-subtle mb-3" />
              <div className="text-[10px] font-semibold uppercase tracking-widest text-text-muted mb-2">Connected Domains</div>
              <div className="space-y-0.5">
                {selectedCluster.domains.map(d => (
                  <button key={d} onClick={() => navigate(`/investigate/${d}`)}
                    className="flex w-full items-center gap-1.5 rounded px-2 py-1.5 text-left font-mono text-xs text-text-secondary hover:bg-white/[0.03] hover:text-text-primary transition-colors"
                  ><ExternalLink className="h-3 w-3 shrink-0 text-text-muted" />{d}</button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
