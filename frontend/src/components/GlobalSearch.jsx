import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search } from 'lucide-react';
import Fuse from 'fuse.js';
import { useData } from '@/context/DataContext';

export default function GlobalSearch() {
  const { fpMatches } = useData();
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [open, setOpen] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const ref = useRef(null);
  const fuseRef = useRef(null);

  useEffect(() => {
    if (fpMatches && fpMatches.length > 0) {
      const seen = new Set();
      const items = fpMatches.filter(m => {
        if (seen.has(m.domain)) return false;
        seen.add(m.domain);
        return true;
      });
      fuseRef.current = new Fuse(items, {
        keys: ['domain', 'fp_name'],
        threshold: 0.3,
      });
    }
  }, [fpMatches]);

  useEffect(() => {
    function handleClickOutside(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  function handleSearch(value) {
    setQuery(value);
    setSelectedIndex(-1);
    if (!value.trim() || !fuseRef.current) {
      setResults([]);
      setOpen(false);
      return;
    }
    const hits = fuseRef.current.search(value).slice(0, 10);
    setResults(hits.map(h => h.item));
    setOpen(true);
  }

  function handleSelect(domain) {
    setQuery('');
    setOpen(false);
    setSelectedIndex(-1);
    navigate(`/investigate/${domain}`);
  }

  function handleKeyDown(e) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex(prev => Math.min(prev + 1, results.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex(prev => Math.max(prev - 1, -1));
    } else if (e.key === 'Enter') {
      if (selectedIndex >= 0 && results[selectedIndex]) {
        handleSelect(results[selectedIndex].domain);
      } else if (query.trim()) {
        setOpen(false);
        navigate(`/investigate/${query.trim()}`);
      }
    } else if (e.key === 'Escape') {
      setOpen(false);
    }
  }

  return (
    <div ref={ref} className="relative">
      <div className="relative">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
        <input
          type="text"
          value={query}
          onChange={e => handleSearch(e.target.value)}
          onKeyDown={handleKeyDown}
          onFocus={() => { if (results.length > 0) setOpen(true); }}
          placeholder="Search domains…"
          className="w-72 rounded-lg border border-border-subtle bg-surface py-2 pl-9 pr-3 text-sm text-gray-100 placeholder-gray-500 transition-all duration-200 focus:border-blue-500/50 focus:outline-none focus:ring-1 focus:ring-blue-500/20"
        />
      </div>
      {open && results.length > 0 && (
        <div className="absolute right-0 top-full z-50 mt-2 w-96 overflow-hidden rounded-xl border border-border-subtle shadow-2xl animate-slide-down"
          style={{ background: 'rgba(19, 27, 46, 0.98)', backdropFilter: 'blur(16px)' }}
        >
          {results.map((r, i) => (
            <button
              key={r.domain}
              onClick={() => handleSelect(r.domain)}
              className={`flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors ${i === selectedIndex
                  ? 'bg-blue-500/10 text-blue-300'
                  : 'text-gray-300 hover:bg-white/5'
                }`}
            >
              <span className="font-mono text-sm">{r.domain}</span>
              <span className="ml-auto truncate text-xs text-gray-500">{r.fp_name}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
