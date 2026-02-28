import { useState, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useData } from '@/context/DataContext';
import SigmaGraph from '@/components/SigmaGraph';
import { Network, Sliders, ExternalLink, BarChart3, ChevronLeft, ChevronRight, X } from 'lucide-react';

const TYPE_META = {
  mx_host: { label: 'MX Host', color: '#3b82f6' },
  ip: { label: 'IP Address', color: '#f97316' },
  registrar_ns: { label: 'Registrar+NS', color: '#22c55e' },
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

  const clusterTable = useMemo(() => buildClusterTable(clusters), [clusters]);

  const filtered = useMemo(() => {
    if (!search) return clusterTable;
    const l = search.toLowerCase();
    return clusterTable.filter(r => r.label.toLowerCase().includes(l));
  }, [clusterTable, search]);

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
    types: ['mx_host', 'ip', 'registrar_ns'],
    minSize: 0,
  }), []);

  if (loading) {
    return (
      <div className="flex h-80 items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-7 w-7 animate-spin rounded-full border-2 border-white/10 border-t-white/50" />
          <span className="text-xs text-text-muted">Loading clusters…</span>
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

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-text-primary">Infrastructure Clusters</h1>
          <p className="text-xs text-text-muted">
            {clusterTable.length.toLocaleString()} clusters linking {clusters?.nodes?.length?.toLocaleString() || 0} nodes
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
            <input type="text" placeholder="Search clusters by MX, IP, or registrar…" value={search}
              onChange={e => { setSearch(e.target.value); setPage(0); }}
              className="w-full rounded-md border border-border-subtle bg-[#0a0a0a] py-1.5 px-3 text-xs text-text-primary placeholder-text-muted outline-none focus:border-white/15 transition-colors"
            />
          </div>

          {/* Table */}
          <div className="overflow-x-auto rounded-lg border border-border-subtle bg-[#080808]">
            <table className="intel-table w-full text-left">
              <thead>
                <tr>
                  <th>Infrastructure Node</th>
                  <th>Type</th>
                  <th className="text-right">Connected Domains</th>
                  <th>Top Connected</th>
                </tr>
              </thead>
              <tbody>
                {pageRows.map(row => (
                  <tr key={row.id} onClick={() => { setSelectedCluster(row); setView('graph'); }}>
                    <td><span className="font-mono text-sm text-text-primary">{row.label}</span></td>
                    <td>
                      <span className="inline-flex items-center gap-1.5 text-xs text-text-muted">
                        <span className="h-2 w-2 rounded-full" style={{ backgroundColor: TYPE_META[row.type]?.color || '#888' }} />
                        {TYPE_META[row.type]?.label || row.type}
                      </span>
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
          <div className="relative flex-1 overflow-hidden rounded-lg border border-border-subtle bg-[#050505]">
            {/* Back to table */}
            <button onClick={() => { setView('table'); setSelectedCluster(null); }}
              className="absolute left-3 top-3 z-10 flex items-center gap-1 rounded-md border border-border-subtle bg-[#111] px-2.5 py-1 text-xs text-text-secondary hover:text-text-primary transition-colors"
            ><ChevronLeft className="h-3 w-3" /> Back to table</button>

            {selectedCluster && (
              <div className="absolute right-3 top-3 z-10 rounded-md border border-border-subtle bg-[#111] px-3 py-1.5 text-xs text-text-secondary">
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
            <div className="w-72 shrink-0 overflow-y-auto rounded-lg border border-border-subtle bg-[#0a0a0a] p-4">
              <div className="mb-4">
                <div className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">
                  {TYPE_META[selectedCluster.type]?.label}
                </div>
                <div className="mt-1 break-all font-mono text-base font-bold text-text-primary">{selectedCluster.label}</div>
                <div className="mt-1 text-xs text-text-muted">{selectedCluster.domainCount} connected domains</div>
              </div>
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
