import { useNavigate } from 'react-router-dom';
import { Search, Globe, Fingerprint, Network, TrendingUp } from 'lucide-react';
import { useState } from 'react';
import { useData } from '@/context/DataContext';

export default function InvestigateLanding() {
  const navigate = useNavigate();
  const { stats } = useData();
  const [query, setQuery] = useState('');

  function handleSubmit(e) {
    e.preventDefault();
    if (query.trim()) {
      navigate(`/investigate/${query.trim()}`);
    }
  }

  const statCards = [
    { icon: Globe, label: 'Domains Tracked', value: stats?.total_domains?.toLocaleString() ?? '—', color: '#3b82f6' },
    { icon: Fingerprint, label: 'FP Matches', value: stats?.matched_domains?.toLocaleString() ?? '—', color: '#f97316' },
    { icon: Network, label: 'Infra Clusters', value: stats?.total_clusters?.toLocaleString() ?? '—', color: '#22c55e' },
    { icon: TrendingUp, label: 'Unique Fingerprints', value: stats?.unique_fingerprints?.toLocaleString() ?? '—', color: '#a855f7' },
  ];

  return (
    <div className="flex flex-col items-center pt-16 pb-12">
      {/* Hero */}
      <div className="relative mb-12 flex flex-col items-center">
        <div className="absolute -top-20 h-64 w-64 rounded-full opacity-20 blur-3xl"
          style={{ background: 'radial-gradient(circle, #2563eb 0%, transparent 70%)' }}
        />

        <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-2xl"
          style={{ background: 'linear-gradient(135deg, #1d4ed8, #2563eb)' }}
        >
          <Search className="h-8 w-8 text-white" strokeWidth={1.5} />
        </div>

        <h1 className="mb-2 text-3xl font-bold tracking-tight text-gray-100">
          Domain Investigation
        </h1>
        <p className="mb-8 max-w-md text-center text-sm text-gray-400">
          Search any domain to view its full intelligence profile — DNS infrastructure,
          fingerprint matches, entity screening, and risk indicators.
        </p>

        {/* Search Bar */}
        <form onSubmit={handleSubmit} className="relative w-full max-w-lg">
          <Search className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Enter a domain to investigate…"
            autoFocus
            className="w-full rounded-xl border border-border-subtle bg-surface-raised py-3.5 pl-12 pr-4 text-base text-gray-100 placeholder-gray-500 transition-all duration-300 focus:border-blue-500/50 focus:outline-none focus:ring-2 focus:ring-blue-500/20 animate-pulse-glow"
          />
        </form>
      </div>

      {/* Stats Grid */}
      <div className="grid w-full max-w-2xl grid-cols-2 gap-4 sm:grid-cols-4">
        {statCards.map(({ icon: Icon, label, value, color }) => (
          <div key={label} className="kpi-card group">
            <Icon className="mb-2 h-5 w-5 transition-colors" style={{ color }} />
            <div className="text-xl font-bold text-gray-100">{value}</div>
            <div className="mt-0.5 text-xs text-gray-500">{label}</div>
          </div>
        ))}
      </div>

      {/* Last Updated */}
      {stats?.last_updated && (
        <p className="mt-8 text-xs text-gray-600">
          Data last updated: {new Date(stats.last_updated).toLocaleDateString('en-US', {
            year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit'
          })}
        </p>
      )}
    </div>
  );
}
