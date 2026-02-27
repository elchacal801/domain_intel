import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import Fuse from 'fuse.js';
import { useData } from '@/context/DataContext';

export default function GlobalSearch() {
  const { fpMatches } = useData();
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [open, setOpen] = useState(false);
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
    navigate(`/investigate/${domain}`);
  }

  function handleKeyDown(e) {
    if (e.key === 'Enter' && query.trim()) {
      setOpen(false);
      navigate(`/investigate/${query.trim()}`);
    }
  }

  return (
    <div ref={ref} className="relative">
      <input
        type="text"
        value={query}
        onChange={e => handleSearch(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="Search domains..."
        className="w-64 rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm text-gray-100 placeholder-gray-500 focus:border-blue-500 focus:outline-none"
      />
      {open && results.length > 0 && (
        <div className="absolute top-full left-0 z-50 mt-1 w-80 rounded-md border border-border-subtle bg-surface-raised shadow-lg">
          {results.map(r => (
            <button
              key={r.domain}
              onClick={() => handleSelect(r.domain)}
              className="block w-full px-3 py-2 text-left text-sm hover:bg-gray-700"
            >
              <span className="font-mono">{r.domain}</span>
              <span className="ml-2 text-xs text-gray-400">{r.fp_name}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
