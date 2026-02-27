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
import { useData } from '@/context/DataContext';
import ConfidenceBadge from '@/components/ConfidenceBadge';
import FlameBadge from '@/components/FlameBadge';

/* ---------- KPI card ---------- */

function KpiCard({ label, value }) {
  return (
    <div className="rounded-lg border border-border-subtle bg-surface-raised p-4">
      <div className="text-2xl font-bold text-gray-100">
        {value ?? '--'}
      </div>
      <div className="text-xs text-gray-500">{label}</div>
    </div>
  );
}

/* ---------- MultiSelectFilter ---------- */

function MultiSelectFilter({ label, options, selected, onChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  // Close on outside click
  useEffect(() => {
    function handleClick(e) {
      if (ref.current && !ref.current.contains(e.target)) {
        setOpen(false);
      }
    }
    if (open) {
      document.addEventListener('mousedown', handleClick);
      return () => document.removeEventListener('mousedown', handleClick);
    }
  }, [open]);

  const toggleItem = useCallback(
    (item) => {
      onChange((prev) =>
        prev.includes(item)
          ? prev.filter((x) => x !== item)
          : [...prev, item],
      );
    },
    [onChange],
  );

  const buttonLabel =
    selected.length === 0
      ? label
      : `${label} (${selected.length})`;

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={`rounded-md border px-3 py-1.5 text-sm transition-colors ${
          selected.length > 0
            ? 'border-blue-500 bg-blue-950/40 text-blue-300'
            : 'border-border-subtle bg-surface-raised text-gray-300 hover:bg-gray-800'
        }`}
      >
        {buttonLabel}
        <span className="ml-1.5 text-xs text-gray-500">{open ? '\u25B2' : '\u25BC'}</span>
      </button>
      {open && (
        <div className="absolute left-0 z-50 mt-1 max-h-60 w-56 overflow-y-auto rounded-md border border-border-subtle bg-surface-raised shadow-lg">
          {options.length === 0 ? (
            <div className="px-3 py-2 text-xs text-gray-500">No options</div>
          ) : (
            options.map((opt) => (
              <label
                key={opt}
                className="flex cursor-pointer items-center gap-2 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-800"
              >
                <input
                  type="checkbox"
                  checked={selected.includes(opt)}
                  onChange={() => toggleItem(opt)}
                  className="rounded border-gray-600"
                />
                <span className="truncate">{opt}</span>
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
        <span className="font-mono text-blue-400">{info.getValue()}</span>
      ),
    }),
    columnHelper.accessor('fp_id', {
      header: 'Fingerprint',
      cell: (info) => (
        <span className="font-mono text-xs text-gray-300">{info.getValue()}</span>
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
        const ids = String(raw)
          .split(/[,;]+/)
          .map((s) => s.trim())
          .filter(Boolean);
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
        <span className="text-sm text-gray-300">{info.getValue()}</span>
      ),
    }),
    columnHelper.accessor('registrar', {
      header: 'Registrar',
      cell: (info) => (
        <span className="max-w-[150px] truncate text-xs text-gray-400" title={info.getValue()}>
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

  // Filter state
  const [domainFilter, setDomainFilter] = useState('');
  const [selectedFpIds, setSelectedFpIds] = useState([]);
  const [selectedTlds, setSelectedTlds] = useState([]);
  const [selectedRegistrars, setSelectedRegistrars] = useState([]);

  // Sorting state
  const [sorting, setSorting] = useState([]);

  // Derive unique filter options
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

  // Filtered data
  const filteredData = useMemo(() => {
    if (!fpMatches) return [];
    let data = fpMatches;

    if (domainFilter) {
      const lower = domainFilter.toLowerCase();
      data = data.filter((r) => r.domain?.toLowerCase().includes(lower));
    }
    if (selectedFpIds.length > 0) {
      data = data.filter((r) => selectedFpIds.includes(r.fp_id));
    }
    if (selectedTlds.length > 0) {
      data = data.filter((r) => selectedTlds.includes(r.tld));
    }
    if (selectedRegistrars.length > 0) {
      data = data.filter((r) => selectedRegistrars.includes(r.registrar));
    }
    return data;
  }, [fpMatches, domainFilter, selectedFpIds, selectedTlds, selectedRegistrars]);

  const hasActiveFilters =
    domainFilter !== '' ||
    selectedFpIds.length > 0 ||
    selectedTlds.length > 0 ||
    selectedRegistrars.length > 0;

  function clearFilters() {
    setDomainFilter('');
    setSelectedFpIds([]);
    setSelectedTlds([]);
    setSelectedRegistrars([]);
  }

  // Columns (stable reference)
  const columns = useMemo(() => buildColumns(), []);

  // Table instance
  const table = useReactTable({
    data: filteredData,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: {
      pagination: { pageSize: PAGE_SIZE },
    },
  });

  const pageIndex = table.getState().pagination.pageIndex;
  const pageCount = table.getPageCount();

  return (
    <div className="space-y-4">
      {/* ---------- Stats Bar ---------- */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard label="Total Domains" value={stats?.total_domains} />
        <KpiCard label="FP Matches" value={stats?.matched_domains} />
        <KpiCard label="Unique FPs" value={stats?.unique_fingerprints} />
        <KpiCard label="Clusters" value={stats?.total_clusters} />
      </div>

      {/* ---------- Filter Bar ---------- */}
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="text"
          placeholder="Filter by domain..."
          value={domainFilter}
          onChange={(e) => setDomainFilter(e.target.value)}
          className="rounded-md border border-border-subtle bg-surface-raised px-3 py-1.5 text-sm text-gray-200 placeholder-gray-500 outline-none focus:border-blue-500"
        />
        <MultiSelectFilter
          label="Fingerprint"
          options={fpIdOptions}
          selected={selectedFpIds}
          onChange={setSelectedFpIds}
        />
        <MultiSelectFilter
          label="TLD"
          options={tldOptions}
          selected={selectedTlds}
          onChange={setSelectedTlds}
        />
        <MultiSelectFilter
          label="Registrar"
          options={registrarOptions}
          selected={selectedRegistrars}
          onChange={setSelectedRegistrars}
        />
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            className="rounded-md border border-border-subtle px-3 py-1.5 text-sm text-gray-400 transition-colors hover:bg-gray-800 hover:text-gray-200"
          >
            Clear filters
          </button>
        )}
        <span className="ml-auto text-xs text-gray-500">
          {filteredData.length} result{filteredData.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* ---------- Table ---------- */}
      <div className="overflow-x-auto rounded-lg border border-border-subtle">
        <table className="w-full text-left text-sm">
          <thead className="bg-surface text-xs uppercase text-gray-500">
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((header) => (
                  <th
                    key={header.id}
                    className={`px-4 py-3 font-medium ${
                      header.column.getCanSort()
                        ? 'cursor-pointer select-none hover:text-gray-300'
                        : ''
                    }`}
                    onClick={header.column.getToggleSortingHandler()}
                  >
                    <div className="flex items-center gap-1">
                      {flexRender(
                        header.column.columnDef.header,
                        header.getContext(),
                      )}
                      {{
                        asc: ' \u2191',
                        desc: ' \u2193',
                      }[header.column.getIsSorted()] ?? ''}
                    </div>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-4 py-8 text-center text-gray-500"
                >
                  No matches found
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  className="cursor-pointer border-t border-border-subtle hover:bg-gray-800/50"
                  onClick={() =>
                    navigate(`/investigate/${row.original.domain}`)
                  }
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-4 py-2.5">
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext(),
                      )}
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
        <div className="flex items-center justify-between text-sm text-gray-400">
          <span>
            Page {pageIndex + 1} of {pageCount}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
              className="rounded-md border border-border-subtle px-3 py-1 text-sm transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Previous
            </button>
            <button
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
              className="rounded-md border border-border-subtle px-3 py-1 text-sm transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
