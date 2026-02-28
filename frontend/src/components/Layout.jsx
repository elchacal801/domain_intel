import { NavLink, Outlet } from 'react-router-dom';
import { Shield } from 'lucide-react';
import GlobalSearch from './GlobalSearch';
import { useData } from '@/context/DataContext';

const NAV_ITEMS = [
  { to: '/matches', label: 'Matches' },
  { to: '/investigate', label: 'Investigate' },
  { to: '/clusters', label: 'Clusters' },
  { to: '/briefing', label: 'Intel Briefing' },
];

export default function Layout() {
  const { loading, stats } = useData();

  return (
    <div className="min-h-screen flex flex-col" style={{ background: '#050505' }}>
      {/* Nav */}
      <nav className="sticky top-0 z-50 border-b border-border-subtle"
        style={{ background: 'rgba(5, 5, 5, 0.95)', backdropFilter: 'blur(12px)' }}
      >
        <div className="mx-auto flex max-w-screen-2xl items-center justify-between px-5 py-2.5">
          <div className="flex items-center gap-7">
            <div className="flex items-center gap-2.5">
              <Shield className="h-5 w-5 text-white/60" strokeWidth={2} />
              <span className="text-base font-bold tracking-tight text-white/90">
                Domain Intel
              </span>
            </div>
            <div className="flex gap-1">
              {NAV_ITEMS.map(item => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `rounded-md px-3 py-1.5 text-xs font-medium transition-all duration-200 ${isActive ? 'nav-link-active' : 'nav-link-inactive'
                    }`
                  }
                >
                  {item.label}
                </NavLink>
              ))}
            </div>
          </div>
          <GlobalSearch />
        </div>
      </nav>

      {/* Main */}
      <main className="mx-auto w-full max-w-screen-2xl flex-1 px-5 py-5">
        {loading ? (
          <div className="flex h-80 items-center justify-center">
            <div className="flex flex-col items-center gap-4">
              <div className="h-8 w-8 animate-spin rounded-full border-2 border-white/10 border-t-white/50" />
              <span className="text-xs text-text-muted">Loading intelligence…</span>
            </div>
          </div>
        ) : (
          <div className="animate-fade-in">
            <Outlet />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-border-subtle px-5 py-3">
        <div className="mx-auto flex max-w-screen-2xl items-center justify-between">
          <span className="text-[10px] text-text-muted">
            Domain Intelligence Platform
          </span>
          {stats?.last_updated && (
            <span className="text-[10px] text-text-muted">
              Data: {new Date(stats.last_updated).toLocaleDateString('en-US', {
                year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
              })}
            </span>
          )}
        </div>
      </footer>
    </div>
  );
}
