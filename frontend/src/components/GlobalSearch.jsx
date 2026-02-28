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
  const inputRef = useRef(null);
  const fuseRef = useRef(null);

  useEffect(() => {
    if (fpMatches?.length > 0) {
      const seen = new Set();
      const items = fpMatches.filter(m => {
        if (seen.has(m.domain)) return false;
        seen.add(m.domain);
        return true;
      });
      fuseRef.current = new Fuse(items, { keys: ['domain', 'fp_name'], threshold: 0.3 });
    }
  }, [fpMatches]);

  useEffect(() => {
    const handle = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handle);
    return () => document.removeEventListener('mousedown', handle);
  }, []);

  // "/" keyboard shortcut to focus search
  useEffect(() => {
    function handleGlobalKey(e) {
      if (e.key === '/' && !['INPUT', 'TEXTAREA'].includes(document.activeElement?.tagName)) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    }
    document.addEventListener('keydown', handleGlobalKey);
    return () => document.removeEventListener('keydown', handleGlobalKey);
  }, []);

  function handleSearch(value) {
    setQuery(value);
    setSelectedIndex(-1);
    if (!value.trim() || !fuseRef.current) { setResults([]); setOpen(false); return; }
    const hits = fuseRef.current.search(value).slice(0, 10);
    setResults(hits.map(h => h.item));
    setOpen(true);
  }

  function handleSelect(domain) {
    setQuery(''); setOpen(false); setSelectedIndex(-1);
    navigate(`/investigate/${domain}`);
  }

  function handleKeyDown(e) {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelectedIndex(p => Math.min(p + 1, results.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setSelectedIndex(p => Math.max(p - 1, -1)); }
    else if (e.key === 'Enter') {
      if (selectedIndex >= 0 && results[selectedIndex]) handleSelect(results[selectedIndex].domain);
      else if (query.trim()) { setOpen(false); navigate(`/investigate/${query.trim()}`); }
    } else if (e.key === 'Escape') setOpen(false);
  }

  return (
    <div ref={ref} className="relative">
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-muted" />
        <input ref={inputRef} type="text" value={query}
          onChange={e => handleSearch(e.target.value)} onKeyDown={handleKeyDown}
          onFocus={() => { if (results.length > 0) setOpen(true); }}
          placeholder="Search…"
          className="w-52 rounded-md border py-1.5 pl-8 pr-8 text-xs outline-none transition-colors"
          style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }}
        />
        <span className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded border border-border-subtle px-1 py-0.5 text-[8px] text-text-muted font-mono">/</span>
      </div>
      {open && results.length > 0 && (
        <div className="absolute right-0 top-full z-50 mt-1.5 w-80 overflow-hidden rounded-lg border shadow-2xl animate-slide-down"
          style={{ background: 'var(--bg-nav)', borderColor: 'var(--border-subtle)' }}>
          {results.map((r, i) => (
            <button key={r.domain} onClick={() => handleSelect(r.domain)}
              className="flex w-full items-center gap-2 px-3 py-2 text-left transition-colors hover:bg-[var(--nav-inactive-hover-bg)]"
              style={{
                background: i === selectedIndex ? 'var(--nav-inactive-hover-bg)' : 'transparent',
                color: i === selectedIndex ? 'var(--text-primary)' : 'var(--text-secondary)'
              }}
            >
              <span className="font-mono text-xs">{r.domain}</span>
              <span className="ml-auto truncate text-[10px]" style={{ color: 'var(--text-muted)' }}>{r.fp_name}</span>
            </button>
          ))}
        </div>
      )}
      {open && query.trim() && results.length === 0 && (
        <div className="absolute right-0 top-full z-50 mt-1.5 w-80 rounded-lg border p-3 text-xs animate-slide-down"
          style={{ background: 'var(--bg-nav)', borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}>
          No matches — press Enter to investigate "{query.trim()}"
        </div>
      )}
    </div>
  );
}
