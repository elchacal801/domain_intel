import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';

const DataContext = createContext(null);

/**
 * Derive the shard key for a domain (matches build_frontend_data.py logic).
 * First character lowercase: a-z, 0-9, or "misc".
 */
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
  const [loading, setLoading] = useState(true);

  // Cache loaded shards: key -> {domain: data}
  const shardCacheRef = useRef(new Map());

  useEffect(() => {
    async function loadInitialData() {
      try {
        const [statsRes, fpRes, clustersRes] = await Promise.all([
          fetch('./data/stats.json').then(r => r.ok ? r.json() : null),
          fetch('./data/fingerprint_matches.json').then(r => r.ok ? r.json() : null),
          fetch('./data/clusters.json').then(r => r.ok ? r.json() : null),
        ]);
        setStats(statsRes);
        setFpMatches(fpRes || []);
        setClusters(clustersRes || { nodes: [], edges: [] });
      } catch (err) {
        console.error('Failed to load data:', err);
      } finally {
        setLoading(false);
      }
    }
    loadInitialData();
  }, []);

  /**
   * Load a domain's data by fetching its shard file on demand.
   * Returns the domain record or null if not found.
   */
  const loadDomain = useCallback(async (domain) => {
    if (!domain) return null;

    const key = shardKey(domain);
    const cache = shardCacheRef.current;

    // Return from cache if shard already loaded
    if (cache.has(key)) {
      return cache.get(key)[domain] || null;
    }

    // Fetch the shard
    try {
      const res = await fetch(`./data/domains_${key}.json`);
      if (!res.ok) {
        cache.set(key, {});
        return null;
      }
      const data = await res.json();
      cache.set(key, data);
      return data[domain] || null;
    } catch {
      cache.set(key, {});
      return null;
    }
  }, []);

  return (
    <DataContext.Provider value={{ stats, fpMatches, clusters, loadDomain, loading }}>
      {children}
    </DataContext.Provider>
  );
}

export function useData() {
  const ctx = useContext(DataContext);
  if (!ctx) throw new Error('useData must be used within DataProvider');
  return ctx;
}
