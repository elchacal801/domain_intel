import { useState, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useData } from '@/context/DataContext';
import SigmaGraph from '@/components/SigmaGraph';
import { Network, Sliders, ExternalLink } from 'lucide-react';

const INFRA_TYPES = [
  { key: 'mx_host', label: 'MX Host', color: '#3b82f6' },
  { key: 'ip', label: 'IP Address', color: '#f97316' },
  { key: 'registrar_ns', label: 'Registrar+NS', color: '#22c55e' },
];

export default function ClusterView() {
  const { clusters, loading } = useData();
  const navigate = useNavigate();

  const [selectedNode, setSelectedNode] = useState(null);
  const [typeFilters, setTypeFilters] = useState(['mx_host', 'ip', 'registrar_ns']);
  const [minSize, setMinSize] = useState(3);

  const filters = useMemo(
    () => ({ types: typeFilters, minSize }),
    [typeFilters, minSize],
  );

  const toggleType = useCallback((key) => {
    setTypeFilters((prev) =>
      prev.includes(key) ? prev.filter((t) => t !== key) : [...prev, key],
    );
  }, []);

  const handleNodeClick = useCallback(
    (nodeInfo) => {
      if (!nodeInfo) { setSelectedNode(null); return; }
      if (nodeInfo.type === 'domain') { navigate(`/investigate/${nodeInfo.label}`); return; }
      setSelectedNode(nodeInfo);
    },
    [navigate],
  );

  const counts = useMemo(() => {
    if (!clusters) return { nodes: 0, edges: 0 };
    const typeSet = new Set(typeFilters);
    const infraIds = new Set();
    for (const node of clusters.nodes || []) {
      if (node.type !== 'domain' && typeSet.has(node.type)) infraIds.add(node.id);
    }
    const domainIds = new Set();
    let edgeCount = 0;
    for (const edge of clusters.edges || []) {
      const srcIsInfra = infraIds.has(edge.source);
      const tgtIsInfra = infraIds.has(edge.target);
      if (srcIsInfra || tgtIsInfra) {
        edgeCount++;
        if (!srcIsInfra) domainIds.add(edge.source);
        if (!tgtIsInfra) domainIds.add(edge.target);
      }
    }
    return { nodes: infraIds.size + domainIds.size, edges: edgeCount };
  }, [clusters, typeFilters]);

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="h-10 w-10 animate-spin rounded-full border-2 border-blue-500/30 border-t-blue-500" />
          <span className="text-sm text-gray-500">Loading cluster data…</span>
        </div>
      </div>
    );
  }

  if (!clusters || (clusters.nodes?.length ?? 0) === 0) {
    return (
      <div className="flex h-96 flex-col items-center justify-center gap-4">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gray-800/50">
          <Network className="h-8 w-8 text-gray-600" />
        </div>
        <p className="text-gray-500">No cluster data available.</p>
      </div>
    );
  }

  return (
    <div className="flex h-[calc(100vh-5rem)] gap-4">
      {/* Graph area */}
      <div className="relative flex-1 overflow-hidden rounded-xl border border-border-subtle"
        style={{ background: 'rgba(6, 10, 20, 0.8)' }}
      >
        {/* Controls overlay */}
        <div className="absolute left-4 top-4 z-10 rounded-xl border border-border-subtle p-4"
          style={{ background: 'rgba(19, 27, 46, 0.92)', backdropFilter: 'blur(16px)' }}
        >
          {/* Header */}
          <div className="mb-4 flex items-center gap-2">
            <Sliders className="h-4 w-4 text-gray-500" />
            <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">Controls</span>
          </div>

          {/* Node Types */}
          <div className="mb-4">
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-gray-500">Node Types</div>
            <div className="space-y-1.5">
              {INFRA_TYPES.map(({ key, label, color }) => (
                <label key={key} className="flex cursor-pointer items-center gap-2.5 text-sm text-gray-300">
                  <input
                    type="checkbox"
                    checked={typeFilters.includes(key)}
                    onChange={() => toggleType(key)}
                    className="rounded border-gray-600 bg-transparent text-blue-500 focus:ring-blue-500/30"
                  />
                  <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />
                  {label}
                </label>
              ))}
            </div>
          </div>

          {/* Min Cluster Size */}
          <div className="mb-4">
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-gray-500">Min Cluster Size</div>
            <div className="flex items-center gap-3">
              <input
                type="range" min={3} max={20} value={minSize}
                onChange={(e) => setMinSize(Number(e.target.value))}
                className="w-28 accent-blue-500"
              />
              <span className="font-mono text-sm text-gray-300">{minSize}</span>
            </div>
          </div>

          {/* Counts */}
          <div className="rounded-lg border border-border-subtle bg-surface p-2 text-center">
            <span className="font-mono text-xs text-gray-500">
              {counts.nodes.toLocaleString()} nodes · {counts.edges.toLocaleString()} edges
            </span>
          </div>
        </div>

        {/* Sigma graph */}
        <SigmaGraph data={clusters} onClickNode={handleNodeClick} filters={filters} />
      </div>

      {/* Detail sidebar */}
      {selectedNode && selectedNode.type !== 'domain' && (
        <div className="w-80 shrink-0 overflow-y-auto rounded-xl border border-border-subtle p-5 animate-fade-in"
          style={{ background: 'linear-gradient(180deg, rgba(19, 27, 46, 0.95), rgba(11, 17, 32, 0.98))' }}
        >
          {/* Node info */}
          <div className="mb-5">
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-gray-500">
              {INFRA_TYPES.find((t) => t.key === selectedNode.type)?.label || selectedNode.type}
            </div>
            <div className="mt-2 break-all font-mono text-lg font-bold text-gray-100">
              {selectedNode.label}
            </div>
          </div>

          {/* Divider */}
          <div className="mb-4 h-px bg-border-subtle" />

          {/* Connected domains */}
          <div>
            <div className="mb-3 text-[10px] font-semibold uppercase tracking-widest text-gray-500">
              Connected Domains ({selectedNode.domains?.length || 0})
            </div>
            <div className="space-y-1">
              {(selectedNode.domains || []).map((domain) => (
                <button
                  key={domain}
                  onClick={() => navigate(`/investigate/${domain}`)}
                  className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left font-mono text-sm text-blue-400 transition-colors hover:bg-blue-500/10"
                >
                  <ExternalLink className="h-3.5 w-3.5 shrink-0 text-gray-600" />
                  {domain}
                </button>
              ))}
              {(!selectedNode.domains || selectedNode.domains.length === 0) && (
                <div className="text-sm text-gray-600">No connected domains</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
