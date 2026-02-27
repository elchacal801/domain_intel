import { NavLink, Outlet } from 'react-router-dom';
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
    <div className="min-h-screen bg-gray-950">
      <nav className="border-b border-border-subtle bg-surface">
        <div className="mx-auto flex max-w-screen-2xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-6">
            <span className="text-lg font-bold text-gray-100">Domain Intel</span>
            <div className="flex gap-1">
              {NAV_ITEMS.map(item => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                      isActive
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
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
      <main className="mx-auto max-w-screen-2xl p-4">
        {loading ? (
          <div className="flex h-64 items-center justify-center">
            <div className="text-gray-400">Loading data...</div>
          </div>
        ) : (
          <Outlet />
        )}
      </main>
    </div>
  );
}
