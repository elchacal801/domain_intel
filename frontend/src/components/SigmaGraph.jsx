import { useRef, useEffect, useCallback, useMemo } from 'react';
import Graph from 'graphology';
import Sigma from 'sigma';
import forceAtlas2 from 'graphology-layout-forceatlas2';

const NODE_COLORS = {
  mx_host: '#3b82f6',
  ip: '#f97316',
  registrar_ns: '#22c55e',
  domain: '#94a3b8',
};

const HIGHLIGHT_COLOR = '#fbbf24';
const DIM_COLOR = '#1f2937';

/**
 * Build a filtered graphology Graph from cluster data.
 *
 * 1. Add infrastructure nodes that pass the type filter
 * 2. Add domain nodes only if they have edges to visible infra nodes
 * 3. Remove infra nodes with degree < minSize and their orphaned domain nodes
 */
function buildGraph(data, filters) {
  const { types = [], minSize = 3 } = filters || {};

  const graph = new Graph();

  if (!data || !data.nodes || !data.edges) return graph;

  const typeSet = new Set(types);

  // Build a lookup map for nodes (used throughout)
  const nodeMap = new Map();
  for (const node of data.nodes) {
    nodeMap.set(node.id, node);
  }

  // Step 1: Add infrastructure nodes that pass the type filter
  const infraIds = new Set();
  for (const node of data.nodes) {
    if (node.type !== 'domain' && typeSet.has(node.type)) {
      infraIds.add(node.id);
    }
  }

  // Step 2: Determine which domain nodes connect to visible infra nodes
  const domainIds = new Set();
  const validEdges = [];
  for (const edge of data.edges) {
    const srcIsInfra = infraIds.has(edge.source);
    const tgtIsInfra = infraIds.has(edge.target);
    const srcNode = nodeMap.get(edge.source);
    const tgtNode = nodeMap.get(edge.target);
    const srcIsDomain = !srcIsInfra && srcNode?.type === 'domain';
    const tgtIsDomain = !tgtIsInfra && tgtNode?.type === 'domain';

    if ((srcIsInfra && tgtIsDomain) || (tgtIsInfra && srcIsDomain)) {
      validEdges.push(edge);
      if (srcIsDomain) domainIds.add(edge.source);
      if (tgtIsDomain) domainIds.add(edge.target);
    } else if (srcIsInfra && tgtIsInfra) {
      validEdges.push(edge);
    }
  }

  // Add infra nodes to graph
  for (const id of infraIds) {
    const node = nodeMap.get(id);
    if (node) {
      graph.addNode(id, {
        label: node.label,
        size: node.size || 10,
        color: NODE_COLORS[node.type] || NODE_COLORS.domain,
        type: node.type,
        x: Math.random() * 100,
        y: Math.random() * 100,
      });
    }
  }

  // Add domain nodes
  for (const id of domainIds) {
    const node = nodeMap.get(id);
    if (node) {
      graph.addNode(id, {
        label: node.label,
        size: node.size || 5,
        color: NODE_COLORS.domain,
        type: 'domain',
        x: Math.random() * 100,
        y: Math.random() * 100,
      });
    }
  }

  // Add edges
  for (const edge of validEdges) {
    if (graph.hasNode(edge.source) && graph.hasNode(edge.target)) {
      const edgeKey = `${edge.source}->${edge.target}`;
      if (!graph.hasEdge(edgeKey)) {
        graph.addEdgeWithKey(edgeKey, edge.source, edge.target);
      }
    }
  }

  // Step 3: Apply min-size filter - remove infra nodes with degree < minSize
  const infraToRemove = [];
  for (const id of infraIds) {
    if (graph.hasNode(id) && graph.degree(id) < minSize) {
      infraToRemove.push(id);
    }
  }

  for (const id of infraToRemove) {
    graph.dropNode(id);
  }

  // Remove orphaned domain nodes (domains with no remaining edges)
  const domainToRemove = [];
  graph.forEachNode((id, attrs) => {
    if (attrs.type === 'domain' && graph.degree(id) === 0) {
      domainToRemove.push(id);
    }
  });

  for (const id of domainToRemove) {
    graph.dropNode(id);
  }

  return graph;
}

export default function SigmaGraph({ data, onClickNode, filters }) {
  const containerRef = useRef(null);
  const sigmaRef = useRef(null);
  const graphRef = useRef(null);
  const highlightStateRef = useRef(null);

  // Memoize the built graph so we only rebuild when data/filters actually change
  const serializedFilters = useMemo(
    () => JSON.stringify(filters),
    [filters],
  );

  const graph = useMemo(
    () => buildGraph(data, filters),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [data, serializedFilters],
  );

  const resetHighlight = useCallback(() => {
    if (!sigmaRef.current) return;
    highlightStateRef.current = null;
    sigmaRef.current.setSetting('nodeReducer', null);
    sigmaRef.current.setSetting('edgeReducer', null);
    sigmaRef.current.refresh();
  }, []);

  const highlightNeighbors = useCallback((nodeId) => {
    if (!sigmaRef.current || !graphRef.current) return;
    const g = graphRef.current;
    const neighbors = new Set(g.neighbors(nodeId));
    neighbors.add(nodeId);

    highlightStateRef.current = neighbors;

    sigmaRef.current.setSetting('nodeReducer', (id, attrs) => {
      if (neighbors.has(id)) {
        // The clicked infra node keeps its color, connected domains get highlight
        if (id === nodeId) return attrs;
        return { ...attrs, color: HIGHLIGHT_COLOR };
      }
      return { ...attrs, color: DIM_COLOR };
    });

    sigmaRef.current.setSetting('edgeReducer', (edgeKey, attrs) => {
      const src = g.source(edgeKey);
      const tgt = g.target(edgeKey);
      if (neighbors.has(src) && neighbors.has(tgt)) {
        return { ...attrs, color: HIGHLIGHT_COLOR };
      }
      return { ...attrs, hidden: true };
    });

    sigmaRef.current.refresh();
  }, []);

  // Main effect: create/recreate sigma when graph changes
  useEffect(() => {
    if (!containerRef.current) return;

    // Kill previous instance
    if (sigmaRef.current) {
      sigmaRef.current.kill();
      sigmaRef.current = null;
    }

    if (graph.order === 0) {
      graphRef.current = graph;
      return;
    }

    // Apply ForceAtlas2 layout
    forceAtlas2.assign(graph, {
      iterations: 100,
      settings: {
        gravity: 1,
        scalingRatio: 10,
        barnesHutOptimize: true,
      },
    });

    graphRef.current = graph;

    const sigma = new Sigma(graph, containerRef.current, {
      renderLabels: true,
      labelRenderedSizeThreshold: 8,
      defaultEdgeColor: '#374151',
      defaultNodeColor: '#94a3b8',
    });

    sigmaRef.current = sigma;
    highlightStateRef.current = null;

    // Click node handler
    sigma.on('clickNode', ({ node }) => {
      const attrs = graph.getNodeAttributes(node);
      if (attrs.type === 'domain') {
        // Domain click: navigate to investigation
        onClickNode?.({ type: 'domain', id: node, label: attrs.label });
      } else {
        // Infrastructure click: highlight neighbors and report
        const domainNeighbors = graph
          .neighbors(node)
          .filter((nid) => graph.getNodeAttributes(nid).type === 'domain')
          .map((nid) => graph.getNodeAttributes(nid).label);

        highlightNeighbors(node);
        onClickNode?.({
          type: attrs.type,
          id: node,
          label: attrs.label,
          domains: domainNeighbors,
        });
      }
    });

    // Click stage handler (empty space)
    sigma.on('clickStage', () => {
      resetHighlight();
      onClickNode?.(null);
    });

    return () => {
      sigma.kill();
      sigmaRef.current = null;
    };
  }, [graph, onClickNode, highlightNeighbors, resetHighlight]);

  return <div ref={containerRef} className="h-full w-full" />;
}
