import { useState, useMemo, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getPaginationRowModel,
  createColumnHelper,
  flexRender,
} from '@tanstack/react-table';
import { Globe, Fingerprint, Network, Hash, Filter, X, ChevronLeft, ChevronRight } from 'lucide-react';
import { useData } from '@/context/DataContext';
import ConfidenceBadge from '@/components/ConfidenceBadge';
import FlameBadge from '@/components/FlameBadge';

/* ---------- KPI card ---------- */

function KpiCard({ icon: Icon, label, value, color }) {
  return (
    <div className="kpi-card group">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-2xl font-bold text-gray-100">{value ?? '—'}</div>
          <div className="mt-0.5 text-xs text-gray-500">{label}</div>
        </div>
        <Icon className="h-8 w-8 opacity-20 transition-opacity group-hover:opacity-40" style={{ color }} />
      </div>
    </div>
  );
}

/* ---------- MultiSelectFilter ---------- */

function MultiSelectFilter({ label, options, selected, onChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    function handleClick(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    if (open) {
      document.addEventListener('mousedown', handleClick);
      return () => document.removeEventListener('mousedown', handleClick);
    }
  }, [open]);

  const toggleItem = useCallback(
    (item) => {
      onChange((prev) =>
        prev.includes(item) ? prev.filter((x) => x !== item) : [...prev, item],
      );
    },
    [onChange],
  );

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm font-medium transition-all duration-200 ${selected.length > 0
            ? 'border-blue-500/40 bg-blue-950/30 text-blue-300'
            : 'border-border-subtle bg-surface-raised text-gray-400 hover:border-gray-600 hover:text-gray-300'
          }`}
      >
        <Filter className="h-3.5 w-3.5" />
        {label}
        {selected.length > 0 && (
          <span className="ml-0.5 rounded-full bg-blue-500/20 px-1.5 text-xs font-semibold text-blue-300">
            {selected.length}
          </span>
        )}
      </button>
      {open && (
        <div className="absolute left-0 z-50 mt-2 max-h-60 w-60 overflow-y-auto rounded-xl border border-border-subtle shadow-2xl animate-slide-down"
          style={{ background: 'rgba(19, 27, 46, 0.98)', backdropFilter: 'blur(16px)' }}
        >
          {options.length === 0 ? (
            <div className="px-3 py-3 text-xs text-gray-500">No options</div>
          ) : (
            options.map((opt) => (
              <label
                key={opt}
                className="flex cursor-pointer items-center gap-2.5 px-3 py-2 text-sm text-gray-300 transition-colors hover:bg-white/5"
              >
                <input
                  type="checkbox"
                  checked={selected.includes(opt)}
                  onChange={() => toggleItem(opt)}
                  className="rounded border-gray-600 bg-transparent text-blue-500 focus:ring-blue-500/30"
                />
                <span className="truncate font-mono text-xs">{opt}</span>
              </label>
            ))
          )}
        </div>
      )}
    </div>
  );
}

/* ---------- Column definitions ---------- */

const columnHelper = createColumnHelper();

function buildColumns() {
  return [
    columnHelper.accessor('domain', {
      header: 'Domain',
      cell: (info) => (
        <span className="font-mono text-sm text-blue-400">{info.getValue()}</span>
      ),
    }),
    columnHelper.accessor('fp_id', {
      header: 'Fingerprint',
      cell: (info) => (
        <span className="rounded-md bg-gray-800/60 px-2 py-0.5 font-mono text-xs text-gray-300">
          {info.getValue()}
        </span>
      ),
    }),
    columnHelper.accessor('confidence', {
      header: 'Confidence',
      cell: (info) => <ConfidenceBadge score={info.getValue()} />,
      sortingFn: (rowA, rowB) => {
        const a = parseInt(rowA.original.confidence, 10) || 0;
        const b = parseInt(rowB.original.confidence, 10) || 0;
        return a - b;
      },
    }),
    columnHelper.accessor('flame_tp_ids', {
      header: 'FLAME TPs',
      cell: (info) => {
        const raw = info.getValue();
        if (!raw) return null;
        const ids = String(raw).split(/[,;]+/).map((s) => s.trim()).filter(Boolean);
        return (
          <div className="flex flex-wrap gap-1">
            {ids.map((tp) => (
              <FlameBadge key={tp} tpId={tp} />
            ))}
          </div>
        );
      },
      enableSorting: false,
    }),
    columnHelper.accessor('tld', {
      header: 'TLD',
      cell: (info) => (
        <span className="text-sm text-gray-400">{info.getValue()}</span>
      ),
    }),
    columnHelper.accessor('registrar', {
      header: 'Registrar',
      cell: (info) => (
        <span className="max-w-[150px] truncate text-xs text-gray-500" title={info.getValue()}>
          {info.getValue()}
        </span>
      ),
    }),
  ];
}

/* ---------- Main component ---------- */

const PAGE_SIZE = 50;

export default function MatchDashboard() {
  const { fpMatches, stats } = useData();
  const navigate = useNavigate();

  const [domainFilter, setDomainFilter] = useState('');
  const [selectedFpIds, setSelectedFpIds] = useState([]);
  const [selectedTlds, setSelectedTlds] = useState([]);
  const [selectedRegistrars, setSelectedRegistrars] = useState([]);
  const [sorting, setSorting] = useState([]);

  const fpIdOptions = useMemo(() => {
    if (!fpMatches) return [];
    return [...new Set(fpMatches.map((r) => r.fp_id).filter(Boolean))].sort();
  }, [fpMatches]);

  const tldOptions = useMemo(() => {
    if (!fpMatches) return [];
    return [...new Set(fpMatches.map((r) => r.tld).filter(Boolean))].sort();
  }, [fpMatches]);

  const registrarOptions = useMemo(() => {
    if (!fpMatches) return [];
    return [...new Set(fpMatches.map((r) => r.registrar).filter(Boolean))].sort();
  }, [fpMatches]);

  const filteredData = useMemo(() => {
    if (!fpMatches) return [];
    let data = fpMatches;
    if (domainFilter) {
      const lower = domainFilter.toLowerCase();
      data = data.filter((r) => r.domain?.toLowerCase().includes(lower));
    }
    if (selectedFpIds.length > 0) data = data.filter((r) => selectedFpIds.includes(r.fp_id));
    if (selectedTlds.length > 0) data = data.filter((r) => selectedTlds.includes(r.tld));
    if (selectedRegistrars.length > 0) data = data.filter((r) => selectedRegistrars.includes(r.registrar));
    return data;
  }, [fpMatches, domainFilter, selectedFpIds, selectedTlds, selectedRegistrars]);

  const hasActiveFilters =
    domainFilter !== '' || selectedFpIds.length > 0 || selectedTlds.length > 0 || selectedRegistrars.length > 0;

  function clearFilters() {
    setDomainFilter('');
    setSelectedFpIds([]);
    setSelectedTlds([]);
    setSelectedRegistrars([]);
  }

  const columns = useMemo(() => buildColumns(), []);

  const table = useReactTable({
    data: filteredData,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: PAGE_SIZE } },
  });

  const pageIndex = table.getState().pagination.pageIndex;
  const pageCount = table.getPageCount();

  return (
    <div className="space-y-5">
      {/* ---------- Stats Bar ---------- */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard icon={Globe} label="Total Domains" value={stats?.total_domains?.toLocaleString()} color="#3b82f6" />
        <KpiCard icon={Fingerprint} label="FP Matches" value={stats?.matched_domains?.toLocaleString()} color="#f97316" />
        <KpiCard icon={Hash} label="Unique FPs" value={stats?.unique_fingerprints?.toLocaleString()} color="#a855f7" />
        <KpiCard icon={Network} label="Clusters" value={stats?.total_clusters?.toLocaleString()} color="#22c55e" />
      </div>

      {/* ---------- Filter Bar ---------- */}
      <div className="glass-card flex flex-wrap items-center gap-3 p-3">
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            placeholder="Filter by domain…"
            value={domainFilter}
            onChange={(e) => setDomainFilter(e.target.value)}
            className="rounded-lg border border-border-subtle bg-surface py-1.5 pl-9 pr-3 text-sm text-gray-200 placeholder-gray-500 outline-none transition-colors focus:border-blue-500/50"
          />
        </div>
        <MultiSelectFilter label="Fingerprint" options={fpIdOptions} selected={selectedFpIds} onChange={setSelectedFpIds} />
        <MultiSelectFilter label="TLD" options={tldOptions} selected={selectedTlds} onChange={setSelectedTlds} />
        <MultiSelectFilter label="Registrar" options={registrarOptions} selected={selectedRegistrars} onChange={setSelectedRegistrars} />
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            className="flex items-center gap-1 rounded-lg border border-border-subtle px-3 py-1.5 text-sm text-gray-400 transition-colors hover:bg-red-500/10 hover:border-red-500/30 hover:text-red-400"
          >
            <X className="h-3.5 w-3.5" />
            Clear
          </button>
        )}
        <span className="ml-auto font-mono text-xs text-gray-600">
          {filteredData.length.toLocaleString()} result{filteredData.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* ---------- Table ---------- */}
      <div className="overflow-x-auto rounded-xl border border-border-subtle"
        style={{ background: 'rgba(11, 17, 32, 0.6)' }}
      >
        <table className="intel-table w-full text-left">
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((header) => (
                  <th
                    key={header.id}
                    className={header.column.getCanSort() ? 'cursor-pointer select-none' : ''}
                    onClick={header.column.getToggleSortingHandler()}
                  >
                    <div className="flex items-center gap-1.5">
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
              <tr>
                <td colSpan={columns.length} className="px-4 py-12 text-center text-gray-500">
                  No matches found
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  onClick={() => navigate(`/investigate/${row.original.domain}`)}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* ---------- Pagination ---------- */}
      {pageCount > 1 && (
        <div className="flex items-center justify-between text-sm">
          <span className="font-mono text-xs text-gray-600">
            Page {pageIndex + 1} of {pageCount}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
              className="flex items-center gap-1 rounded-lg border border-border-subtle px-3 py-1.5 text-sm text-gray-400 transition-all hover:border-blue-500/30 hover:bg-blue-500/5 hover:text-blue-400 disabled:cursor-not-allowed disabled:opacity-30"
            >
              <ChevronLeft className="h-4 w-4" /> Prev
            </button>
            <button
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
              className="flex items-center gap-1 rounded-lg border border-border-subtle px-3 py-1.5 text-sm text-gray-400 transition-all hover:border-blue-500/30 hover:bg-blue-500/5 hover:text-blue-400 disabled:cursor-not-allowed disabled:opacity-30"
            >
              Next <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
