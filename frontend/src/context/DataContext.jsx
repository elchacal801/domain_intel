import { createContext, useContext, useState, useEffect, useCallback } from 'react';

const DataContext = createContext(null);

export function DataProvider({ children }) {
  const [stats, setStats] = useState(null);
  const [fpMatches, setFpMatches] = useState(null);
  const [clusters, setClusters] = useState(null);
  const [domains, setDomains] = useState(null);
  const [loading, setLoading] = useState(true);

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

  const loadDomains = useCallback(async () => {
    if (domains) return domains;
    try {
      const res = await fetch('./data/domains.json');
      if (!res.ok) return {};
      const data = await res.json();
      setDomains(data);
      return data;
    } catch {
      return {};
    }
  }, [domains]);

  return (
    <DataContext.Provider value={{ stats, fpMatches, clusters, domains, loadDomains, loading }}>
      {children}
    </DataContext.Provider>
  );
}

export function useData() {
  const ctx = useContext(DataContext);
  if (!ctx) throw new Error('useData must be used within DataProvider');
  return ctx;
}
