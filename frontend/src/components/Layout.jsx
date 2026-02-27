import { NavLink, Outlet } from 'react-router-dom';
import { Shield } from 'lucide-react';
import GlobalSearch from './GlobalSearch';
import { useData } from '@/context/DataContext';

const NAV_ITEMS = [
  { to: '/matches', label: 'Matches' },
  { to: '/investigate', label: 'Investigate' },
  { to: '/clusters', label: 'Clusters' },
];

export default function Layout() {
  const { loading } = useData();

  return (
    <div className="min-h-screen" style={{ background: '#060a14' }}>
      {/* --- Top Nav --- */}
      <nav className="sticky top-0 z-50 border-b border-border-subtle"
        style={{
          background: 'linear-gradient(180deg, rgba(11, 17, 32, 0.98), rgba(11, 17, 32, 0.92))',
          backdropFilter: 'blur(16px)',
        }}
      >
        <div className="mx-auto flex max-w-screen-2xl items-center justify-between px-5 py-3">
          <div className="flex items-center gap-8">
            {/* Logo */}
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg"
                style={{ background: 'linear-gradient(135deg, #2563eb, #1d4ed8)' }}
              >
                <Shield className="h-4.5 w-4.5 text-white" strokeWidth={2.5} />
              </div>
              <span className="text-lg font-bold tracking-tight text-gray-100">
                Domain Intel
              </span>
            </div>

            {/* Nav Links */}
            <div className="flex gap-1">
              {NAV_ITEMS.map(item => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `rounded-lg px-3.5 py-1.5 text-sm font-medium transition-all duration-200 ${isActive
                      ? 'nav-link-active'
                      : 'nav-link-inactive'
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

      {/* --- Main Content --- */}
      <main className="mx-auto max-w-screen-2xl px-5 py-5">
        {loading ? (
          <div className="flex h-80 items-center justify-center">
            <div className="flex flex-col items-center gap-4">
              <div className="h-10 w-10 animate-spin rounded-full border-2 border-blue-500/30 border-t-blue-500" />
              <span className="text-sm font-medium text-gray-500">Loading intelligence data…</span>
            </div>
          </div>
        ) : (
          <div className="animate-fade-in">
            <Outlet />
          </div>
        )}
      </main>
    </div>
  );
}
