import { useState, useMemo, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  useReactTable, getCoreRowModel, getSortedRowModel,
  getPaginationRowModel, createColumnHelper, flexRender,
} from '@tanstack/react-table';
import { Globe, Fingerprint, Network, Hash, Filter, X, ChevronLeft, ChevronRight, Download, ShieldAlert } from 'lucide-react';
import { useData } from '@/context/DataContext';
import ConfidenceBadge from '@/components/ConfidenceBadge';
import FlameBadge from '@/components/FlameBadge';
import Tooltip from '@/components/Tooltip';
import { fpRegistry, columnTooltips, kpiTooltips } from '@/data/fpRegistry';

/* ---- KPI ---- */
function KpiCard({ icon: Icon, label, value, color, tooltip }) {
  return (
    <Tooltip text={tooltip}>
      <div className="kpi-card group w-full">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-xl font-bold text-text-primary">{value ?? '—'}</div>
            <div className="mt-0.5 text-[11px] text-text-muted">{label}</div>
          </div>
          <Icon className="h-6 w-6 opacity-15 group-hover:opacity-25 transition-opacity" style={{ color }} />
        </div>
      </div>
    </Tooltip>
  );
}

/* ---- MultiSelect Filter ---- */
function MultiSelectFilter({ label, options, selected, onChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return;
    const handle = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handle);
    return () => document.removeEventListener('mousedown', handle);
  }, [open]);
  const toggle = useCallback((item) => {
    onChange(prev => prev.includes(item) ? prev.filter(x => x !== item) : [...prev, item]);
  }, [onChange]);

  return (
    <div className="relative" ref={ref}>
      <button type="button" onClick={() => setOpen(v => !v)}
        className={`flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-all ${selected.length > 0
          ? 'border-white/15 bg-white/5 text-white/80'
          : 'border-border-subtle text-text-muted hover:text-text-secondary hover:border-border-hover'
          }`}
      >
        <Filter className="h-3 w-3" />
        {label}
        {selected.length > 0 && (
          <span className="rounded-full bg-white/10 px-1.5 text-[10px] font-semibold">{selected.length}</span>
        )}
      </button>
      {open && (
        <div className="absolute left-0 z-50 mt-1.5 max-h-52 w-56 overflow-y-auto rounded-lg border border-border-subtle animate-slide-down" style={{ background: 'var(--bg-surface-raised)' }}>
          {options.length === 0 ? (
            <div className="px-3 py-3 text-xs text-text-muted">No options</div>
          ) : options.map(opt => (
            <label key={opt} className="flex cursor-pointer items-center gap-2 px-3 py-1.5 text-xs text-text-secondary hover:bg-white/[0.03] transition-colors">
              <input type="checkbox" checked={selected.includes(opt)} onChange={() => toggle(opt)}
                className="rounded border-white/20 bg-transparent text-white focus:ring-white/20"
              />
              <span className="truncate font-mono">{opt}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

/* ---- Columns ---- */
const ch = createColumnHelper();
function buildColumns() {
  return [
    ch.accessor('domain', {
      header: () => <Tooltip text={columnTooltips.domain}><span>Domain</span></Tooltip>,
      cell: i => <span className="font-mono text-sm text-text-primary">{i.getValue()}</span>,
    }),
    ch.accessor('fp_id', {
      header: () => <Tooltip text={columnTooltips.fp_id}><span>Fingerprint</span></Tooltip>,
      cell: i => {
        const id = i.getValue();
        const fp = fpRegistry[id];
        return (
          <Tooltip text={fp ? `${fp.name}: ${fp.description}` : id}>
            <span className="rounded bg-white/5 px-2 py-0.5 font-mono text-xs text-text-secondary">{id}</span>
          </Tooltip>
        );
      },
    }),
    ch.accessor('confidence', {
      header: () => <Tooltip text={columnTooltips.confidence}><span>Confidence</span></Tooltip>,
      cell: i => <ConfidenceBadge score={i.getValue()} fpId={i.row.original.fp_id} />,
      sortingFn: (a, b) => (parseInt(a.original.confidence) || 0) - (parseInt(b.original.confidence) || 0),
    }),
    ch.accessor('flame_tp_ids', {
      header: () => <Tooltip text={columnTooltips.flame_tp_ids}><span>FLAME TPs</span></Tooltip>,
      cell: i => {
        const raw = i.getValue();
        if (!raw) return null;
        return (
          <div className="flex flex-wrap gap-1">
            {String(raw).split(/[,;]+/).map(s => s.trim()).filter(Boolean).map(tp => (
              <FlameBadge key={tp} tpId={tp} />
            ))}
          </div>
        );
      },
      enableSorting: false,
    }),
    ch.accessor('tld', {
      header: () => <Tooltip text={columnTooltips.tld}><span>TLD</span></Tooltip>,
      cell: i => <span className="text-sm text-text-muted">{i.getValue()}</span>,
    }),
    ch.accessor('registrar', {
      header: () => <Tooltip text={columnTooltips.registrar}><span>Registrar</span></Tooltip>,
      cell: i => <span className="max-w-[140px] truncate text-xs text-text-muted" title={i.getValue()}>{i.getValue()}</span>,
    }),
  ];
}

/* ---- Main ---- */
const PAGE_SIZE = 50;

export default function MatchDashboard() {
  const { fpMatches, stats } = useData();
  const navigate = useNavigate();
  const [domainFilter, setDomainFilter] = useState('');
  const [selectedFpIds, setSelectedFpIds] = useState([]);
  const [selectedTlds, setSelectedTlds] = useState([]);
  const [selectedRegistrars, setSelectedRegistrars] = useState([]);
  const [sorting, setSorting] = useState([]);

  const fpIdOptions = useMemo(() => fpMatches ? [...new Set(fpMatches.map(r => r.fp_id).filter(Boolean))].sort() : [], [fpMatches]);
  const tldOptions = useMemo(() => fpMatches ? [...new Set(fpMatches.map(r => r.tld).filter(Boolean))].sort() : [], [fpMatches]);
  const registrarOptions = useMemo(() => fpMatches ? [...new Set(fpMatches.map(r => r.registrar).filter(Boolean))].sort() : [], [fpMatches]);

  const filteredData = useMemo(() => {
    if (!fpMatches) return [];
    let d = fpMatches;
    if (domainFilter) { const l = domainFilter.toLowerCase(); d = d.filter(r => r.domain?.toLowerCase().includes(l)); }
    if (selectedFpIds.length) d = d.filter(r => selectedFpIds.includes(r.fp_id));
    if (selectedTlds.length) d = d.filter(r => selectedTlds.includes(r.tld));
    if (selectedRegistrars.length) d = d.filter(r => selectedRegistrars.includes(r.registrar));
    return d;
  }, [fpMatches, domainFilter, selectedFpIds, selectedTlds, selectedRegistrars]);

  const hasActive = domainFilter || selectedFpIds.length || selectedTlds.length || selectedRegistrars.length;
  function clearFilters() { setDomainFilter(''); setSelectedFpIds([]); setSelectedTlds([]); setSelectedRegistrars([]); }

  function exportCSV() {
    if (!filteredData.length) return;
    const cols = ['domain', 'fp_id', 'fp_name', 'confidence', 'flame_tp_ids', 'tld', 'registrar'];
    const header = cols.join(',');
    const rows = filteredData.map(r => cols.map(c => {
      const v = String(r[c] ?? '').replace(/"/g, '""');
      return v.includes(',') || v.includes('"') ? `"${v}"` : v;
    }).join(','));
    const csv = [header, ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'fingerprint_matches.csv'; a.click();
    URL.revokeObjectURL(url);
  }

  const columns = useMemo(() => buildColumns(), []);
  const table = useReactTable({
    data: filteredData, columns, state: { sorting }, onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(), initialState: { pagination: { pageSize: PAGE_SIZE } },
  });

  const pageIndex = table.getState().pagination.pageIndex;
  const pageCount = table.getPageCount();

  return (
    <div className="space-y-4">
      {/* Stats */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <KpiCard icon={Globe} label="Total Domains" value={stats?.total_domains?.toLocaleString()} color="#888" tooltip={kpiTooltips.total_domains} />
        <KpiCard icon={Fingerprint} label="FP Matches" value={stats?.matched_domains?.toLocaleString()} color="#f97316" tooltip={kpiTooltips.matched_domains} />
        <KpiCard icon={Hash} label="Unique FPs" value={stats?.unique_fingerprints?.toLocaleString()} color="#888" tooltip={kpiTooltips.unique_fingerprints} />
        <KpiCard icon={Network} label="Clusters" value={stats?.total_clusters?.toLocaleString()} color="#888" tooltip={kpiTooltips.total_clusters} />
        <KpiCard icon={ShieldAlert} label="Entity-Linked" value={stats?.entity_linked_clusters?.toLocaleString()} color="#C0272D" tooltip={kpiTooltips.entity_linked_clusters} />
      </div>

      {/* Filters */}
      <div className="glass-card flex flex-wrap items-center gap-2.5 p-2.5">
        <div className="relative">
          <Filter className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-muted" />
          <input type="text" placeholder="Domain…" value={domainFilter} onChange={e => setDomainFilter(e.target.value)}
            className="rounded-md border border-border-subtle py-1.5 pl-8 pr-3 text-xs text-text-primary placeholder-text-muted outline-none focus:border-white/15 transition-colors w-44"
            style={{ background: 'var(--bg-surface-input)' }}
          />
        </div>
        <MultiSelectFilter label="Fingerprint" options={fpIdOptions} selected={selectedFpIds} onChange={setSelectedFpIds} />
        <MultiSelectFilter label="TLD" options={tldOptions} selected={selectedTlds} onChange={setSelectedTlds} />
        <MultiSelectFilter label="Registrar" options={registrarOptions} selected={selectedRegistrars} onChange={setSelectedRegistrars} />
        {hasActive && (
          <button onClick={clearFilters}
            className="flex items-center gap-1 rounded-md border border-border-subtle px-2.5 py-1.5 text-xs text-text-muted hover:text-red-400 hover:border-red-500/20 transition-colors"
          ><X className="h-3 w-3" /> Clear</button>
        )}
        <button onClick={exportCSV} title="Download filtered matches as CSV"
          className="flex items-center gap-1 rounded-md border border-border-subtle px-2.5 py-1.5 text-xs text-text-muted hover:text-text-primary hover:border-border-hover transition-colors"
        ><Download className="h-3 w-3" /> CSV</button>
        <span className="ml-auto font-mono text-[11px] text-text-muted">
          {filteredData.length.toLocaleString()} result{filteredData.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-border-subtle" style={{ background: 'var(--bg-surface)' }}>
        <table className="intel-table w-full text-left">
          <thead>
            {table.getHeaderGroups().map(hg => (
              <tr key={hg.id}>
                {hg.headers.map(header => (
                  <th key={header.id} className={header.column.getCanSort() ? 'cursor-pointer select-none' : ''}
                    onClick={header.column.getToggleSortingHandler()}
                  >
                    <div className="flex items-center gap-1">
                      {flexRender(header.column.columnDef.header, header.getContext())}
                      {{ asc: ' ↑', desc: ' ↓' }[header.column.getIsSorted()] ?? ''}
                    </div>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.length === 0 ? (
              <tr><td colSpan={columns.length} className="px-4 py-12 text-center text-text-muted">No matches found</td></tr>
            ) : table.getRowModel().rows.map(row => (
              <tr key={row.id} onClick={() => navigate(`/investigate/${row.original.domain}`)}>
                {row.getVisibleCells().map(cell => (
                  <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {pageCount > 1 && (
        <div className="flex items-center justify-between text-xs">
          <span className="font-mono text-text-muted">
            Showing {pageIndex * PAGE_SIZE + 1}–{Math.min((pageIndex + 1) * PAGE_SIZE, filteredData.length)} of {filteredData.length.toLocaleString()}
          </span>
          <div className="flex gap-1.5">
            <button onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}
              className="flex items-center gap-1 rounded-md border border-border-subtle px-2.5 py-1.5 text-text-muted hover:text-text-primary hover:border-border-hover disabled:opacity-20 disabled:cursor-not-allowed transition-colors"
            ><ChevronLeft className="h-3.5 w-3.5" /> Prev</button>
            <button onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}
              className="flex items-center gap-1 rounded-md border border-border-subtle px-2.5 py-1.5 text-text-muted hover:text-text-primary hover:border-border-hover disabled:opacity-20 disabled:cursor-not-allowed transition-colors"
            >Next <ChevronRight className="h-3.5 w-3.5" /></button>
          </div>
        </div>
      )}
    </div>
  );
}
