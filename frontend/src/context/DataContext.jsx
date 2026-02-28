import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';

const DataContext = createContext(null);

function shardKey(domain) {
  if (!domain) return 'misc';
  const first = domain[0].toLowerCase();
  if (/[a-z]/.test(first)) return first;
  if (/[0-9]/.test(first)) return first;
  return 'misc';
}

export function DataProvider({ children }) {
  const [stats, setStats] = useState(null);
  const [fpMatches, setFpMatches] = useState(null);
  const [clusters, setClusters] = useState(null);
  const [shardManifest, setShardManifest] = useState(null);
  const [loading, setLoading] = useState(true);

  const shardCacheRef = useRef(new Map());

  useEffect(() => {
    async function loadInitialData() {
      try {
        const [statsRes, fpRes, clustersRes, manifestRes] = await Promise.all([
          fetch('./data/stats.json').then(r => r.ok ? r.json() : null),
          fetch('./data/fingerprint_matches.json').then(r => r.ok ? r.json() : null),
          fetch('./data/clusters.json').then(r => r.ok ? r.json() : null),
          fetch('./data/domain_shards.json').then(r => r.ok ? r.json() : null),
        ]);
        setStats(statsRes);
        setFpMatches(fpRes || []);
        setClusters(clustersRes || { nodes: [], edges: [] });
        setShardManifest(manifestRes || {});
      } catch (err) {
        console.error('Failed to load data:', err);
      } finally {
        setLoading(false);
      }
    }
    loadInitialData();
  }, []);

  /** Load a single domain's data by fetching its shard. */
  const loadDomain = useCallback(async (domain) => {
    if (!domain) return null;
    const key = shardKey(domain);
    const cache = shardCacheRef.current;
    if (cache.has(key)) return cache.get(key)[domain] || null;
    try {
      const res = await fetch(`./data/domains_${key}.json`);
      if (!res.ok) { cache.set(key, {}); return null; }
      const data = await res.json();
      cache.set(key, data);
      return data[domain] || null;
    } catch { cache.set(key, {}); return null; }
  }, []);

  /** Load an entire shard (for browse mode). Returns {domain: data} dict. */
  const loadShard = useCallback(async (key) => {
    if (!key) return {};
    const cache = shardCacheRef.current;
    if (cache.has(key)) return cache.get(key);
    try {
      const res = await fetch(`./data/domains_${key}.json`);
      if (!res.ok) { cache.set(key, {}); return {}; }
      const data = await res.json();
      cache.set(key, data);
      return data;
    } catch { cache.set(key, {}); return {}; }
  }, []);

  return (
    <DataContext.Provider value={{ stats, fpMatches, clusters, shardManifest, loadDomain, loadShard, loading }}>
      {children}
    </DataContext.Provider>
  );
}

export function useData() {
  const ctx = useContext(DataContext);
  if (!ctx) throw new Error('useData must be used within DataProvider');
  return ctx;
}
