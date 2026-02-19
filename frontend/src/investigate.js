/**
 * investigate.js — Domain Search & Investigation Module
 * Loads the pre-built investigate_index.json and provides:
 *   - Full-text search across all enrichment fields
 *   - Faceted filters (risk, country, ASN, HTTP status)
 *   - Sortable columns with click-to-toggle
 *   - Paginated results (50 per page)
 *   - Detail slide-out panel with pivot links
 *
 * Data format: Array of objects with short keys (see build_investigate_index.py)
 *   d=domain, mx=primary_mx, mi=mx_ip, a=asn, an=asn_name, c=cc,
 *   bp=bgp_prefix, ns=nameservers, rt=risk_tags, rb=rbl_hits,
 *   cd=creation_date, ag=age_days, ox=otx_risk, hs=http_status,
 *   ht=http_title, hv=http_server, ss=https_status, st=https_title,
 *   sv=https_server, rl=risk_level (pre-computed)
 */

import { fetchJSON } from './data.js';

// ─── Constants ───────────────────────────────────────────────
const PAGE_SIZE = 50;
const SEARCH_FIELDS = ['d', 'mx', 'mi', 'an', 'ht', 'st', 'rt', 'ox', 'ns', 'rb', 'hv', 'sv'];
const SORTABLE_COLS = {
    domain: 'd', risk: 'rl', cc: 'c', asn: 'an',
    mx: 'mx', http: 'hs', title: 'ht', server: 'hv',
};

// ─── State ───────────────────────────────────────────────────
let allData = [];
let filtered = [];
let currentPage = 0;
let sortCol = 'domain';
let sortDir = 'asc';
let searchQuery = '';
let filters = { risk: 'all', country: 'all', asn: 'all', status: 'all' };
let selectedRow = null;
let meta = null;

// ─── Helpers ─────────────────────────────────────────────────
function getRiskLevel(row) {
    if (row.rl) return row.rl;
    if (!row.rt && !row.rb && !row.ox) return 'none';
    if ((row.rt || '').includes('FraudScore') || (row.rb || '').includes('spamhaus')) return 'critical';
    if ((row.rt || '').includes('HighRisk')) return 'high';
    if (row.ox) return 'medium';
    return 'low';
}

const RISK_CFG = {
    critical: { bg: 'var(--danger-dim)', color: 'var(--danger)', border: 'rgba(248,81,73,0.3)', label: 'CRIT' },
    high:     { bg: 'var(--warning-dim)', color: 'var(--warning)', border: 'rgba(210,153,34,0.3)', label: 'HIGH' },
    medium:   { bg: 'rgba(210,153,34,0.08)', color: '#d29922', border: 'rgba(210,153,34,0.2)', label: 'MED' },
    low:      { bg: 'var(--success-dim)', color: 'var(--success)', border: 'rgba(63,185,80,0.2)', label: 'LOW' },
    none:     { bg: 'transparent', color: 'var(--text-muted)', border: 'var(--border-subtle)', label: '—' },
};

function riskBadge(level) {
    const c = RISK_CFG[level] || RISK_CFG.none;
    return `<span class="inv-risk-badge" style="background:${c.bg};color:${c.color};border-color:${c.border}">${c.label}</span>`;
}

function statusHTML(code) {
    if (!code) return '<span class="inv-muted">—</span>';
    const n = parseInt(code);
    let cls = 'inv-status-ok';
    if (n >= 300 && n < 400) cls = 'inv-status-redirect';
    else if (n >= 400 && n < 500) cls = 'inv-status-warn';
    else if (n >= 500) cls = 'inv-status-err';
    return `<span class="inv-status ${cls}">${code}</span>`;
}

function trunc(str, n) {
    if (!str) return '';
    return str.length > n ? str.substring(0, n - 1) + '\u2026' : str;
}

function esc(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ─── Filter & Search ─────────────────────────────────────────
function applyFilters() {
    let rows = allData;

    if (searchQuery) {
        const q = searchQuery.toLowerCase();
        rows = rows.filter(r => {
            for (const key of SEARCH_FIELDS) {
                if (r[key] && r[key].toLowerCase().includes(q)) return true;
            }
            return false;
        });
    }

    if (filters.risk !== 'all') rows = rows.filter(r => getRiskLevel(r) === filters.risk);
    if (filters.country !== 'all') rows = rows.filter(r => r.c === filters.country);
    if (filters.asn !== 'all') rows = rows.filter(r => r.an === filters.asn);

    if (filters.status !== 'all') {
        if (filters.status === 'live') rows = rows.filter(r => r.hs === '200' || r.ss === '200');
        else if (filters.status === 'dead') rows = rows.filter(r => !r.hs && !r.ss);
        else if (filters.status === 'blocked') rows = rows.filter(r => r.hs === '403' || r.hs === '401' || r.ss === '403' || r.ss === '401');
    }

    const key = SORTABLE_COLS[sortCol] || 'd';
    rows = rows.slice().sort((a, b) => {
        const av = (a[key] || '').toLowerCase();
        const bv = (b[key] || '').toLowerCase();
        const an = parseFloat(av), bn = parseFloat(bv);
        const cmp = (!isNaN(an) && !isNaN(bn)) ? an - bn : av.localeCompare(bv);
        return sortDir === 'asc' ? cmp : -cmp;
    });

    filtered = rows;
    currentPage = 0;
}

// ─── Render ──────────────────────────────────────────────────
function renderKPIs() {
    const total = filtered.length;
    const live = filtered.filter(r => r.hs === '200' || r.ss === '200').length;
    const crit = filtered.filter(r => getRiskLevel(r) === 'critical').length;
    const high = filtered.filter(r => getRiskLevel(r) === 'high').length;
    const otx = filtered.filter(r => r.ox).length;

    document.getElementById('inv-kpi-results').textContent = total.toLocaleString();
    document.getElementById('inv-kpi-live').textContent = live.toLocaleString();
    document.getElementById('inv-kpi-critical').textContent = crit.toLocaleString();
    document.getElementById('inv-kpi-high').textContent = high.toLocaleString();
    document.getElementById('inv-kpi-otx').textContent = otx.toLocaleString();
}

function renderTable() {
    const tbody = document.getElementById('inv-tbody');
    const start = currentPage * PAGE_SIZE;
    const page = filtered.slice(start, start + PAGE_SIZE);

    let html = '';
    for (let i = 0; i < page.length; i++) {
        const r = page[i];
        const risk = getRiskLevel(r);
        const sel = (selectedRow && selectedRow.d === r.d) ? ' inv-row-selected' : '';
        html += `<tr class="inv-row${sel}" data-idx="${start + i}">
            <td class="inv-col-domain">${esc(r.d)}</td>
            <td>${riskBadge(risk)}</td>
            <td class="inv-col-center">${esc(r.c) || '—'}</td>
            <td class="inv-col-truncate">${esc(trunc(r.an, 18)) || '—'}</td>
            <td class="inv-col-mono inv-col-truncate">${esc(trunc(r.mx, 22)) || '—'}</td>
            <td class="inv-col-center">${statusHTML(r.hs)}</td>
            <td class="inv-col-truncate">${esc(trunc(r.ht || r.st, 35)) || '—'}</td>
            <td class="inv-col-muted">${esc(r.hv || r.sv) || '—'}</td>
            <td class="inv-col-center">${r.ox ? '<span class="inv-otx-dot">\u25CF</span>' : '<span class="inv-muted">—</span>'}</td>
        </tr>`;
    }
    tbody.innerHTML = html;

    // Row click handlers
    tbody.querySelectorAll('.inv-row').forEach(tr => {
        tr.addEventListener('click', () => {
            selectedRow = filtered[parseInt(tr.dataset.idx)];
            renderTable();
            renderDetail();
        });
    });

    // Pagination
    const end = Math.min(start + PAGE_SIZE, filtered.length);
    const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    document.getElementById('inv-page-info').textContent =
        `Showing ${filtered.length > 0 ? start + 1 : 0}\u2013${end} of ${filtered.length.toLocaleString()}`;
    document.getElementById('inv-page-num').textContent = `Page ${currentPage + 1} / ${totalPages}`;
    document.getElementById('inv-prev').disabled = currentPage === 0;
    document.getElementById('inv-next').disabled = currentPage >= totalPages - 1;
}

function renderSortIndicators() {
    document.querySelectorAll('.inv-th').forEach(th => {
        const col = th.dataset.sort;
        const arrow = th.querySelector('.inv-sort-arrow');
        if (!arrow) return;
        if (col === sortCol) {
            arrow.textContent = sortDir === 'asc' ? ' \u25B2' : ' \u25BC';
            th.classList.add('inv-th-active');
        } else {
            arrow.textContent = '';
            th.classList.remove('inv-th-active');
        }
    });
}

function renderDetail() {
    const panel = document.getElementById('inv-detail-panel');
    const overlay = document.getElementById('inv-detail-overlay');

    if (!selectedRow) {
        panel.classList.remove('inv-panel-open');
        overlay.classList.remove('inv-overlay-visible');
        return;
    }
    panel.classList.add('inv-panel-open');
    overlay.classList.add('inv-overlay-visible');

    const r = selectedRow;
    const risk = getRiskLevel(r);

    const sections = [
        { title: 'IDENTITY', fields: [['Domain', r.d, true], ['Created', r.cd || 'Unknown'], ['Age', r.ag ? r.ag + ' days' : 'Unknown']] },
        { title: 'MAIL INFRASTRUCTURE', fields: [['Primary MX', r.mx || 'None', true], ['MX IP', r.mi || 'None', true]] },
        { title: 'NETWORK', fields: [['ASN', r.a ? 'AS' + r.a : 'Unknown', true], ['ASN Name', r.an || 'Unknown'], ['BGP Prefix', r.bp || 'Unknown', true], ['Country', r.c || 'Unknown'], ['Nameservers', (r.ns || 'Unknown').replace(/;/g, '\n')]] },
        { title: 'WEB FINGERPRINT', fields: [['HTTP Status', r.hs || '\u2014'], ['HTTPS Status', r.ss || '\u2014'], ['Title', r.ht || r.st || '\u2014'], ['Server', r.hv || r.sv || '\u2014']] },
        { title: 'THREAT INTELLIGENCE', fields: [['Risk Tags', r.rt || 'None'], ['RBL Hits', r.rb || 'Clean'], ['OTX Intel', r.ox || 'No pulses']] },
    ];

    let html = `<div class="inv-panel-header"><div>
        <div class="inv-panel-domain">${esc(r.d)}</div>
        <div style="margin-top:6px">${riskBadge(risk)}</div>
        </div><button class="inv-panel-close" id="inv-close-btn">\u2715 Close</button></div>
        <div class="inv-panel-body">`;

    for (const s of sections) {
        html += `<div class="inv-panel-section"><div class="inv-panel-section-title">${s.title}</div>`;
        for (const f of s.fields) {
            const mono = f[2] ? ' inv-mono' : '';
            html += `<div class="inv-panel-field"><span class="inv-panel-label">${f[0]}</span><span class="inv-panel-value${mono}">${esc(f[1])}</span></div>`;
        }
        html += '</div>';
    }

    // Pivot links
    html += '<div class="inv-panel-pivots">';
    html += `<a href="https://www.virustotal.com/gui/domain/${encodeURIComponent(r.d)}" target="_blank" rel="noopener" class="inv-pivot-link">VirusTotal \u2197</a>`;
    html += `<a href="https://urlscan.io/search/#domain:${encodeURIComponent(r.d)}" target="_blank" rel="noopener" class="inv-pivot-link">urlscan.io \u2197</a>`;
    if (r.mi) html += `<a href="https://www.shodan.io/host/${encodeURIComponent(r.mi)}" target="_blank" rel="noopener" class="inv-pivot-link">Shodan \u2197</a>`;
    if (r.a) html += `<a href="https://bgp.he.net/AS${encodeURIComponent(r.a)}" target="_blank" rel="noopener" class="inv-pivot-link">BGP HE.net \u2197</a>`;
    html += '</div></div>';

    panel.innerHTML = html;

    document.getElementById('inv-close-btn').addEventListener('click', () => {
        selectedRow = null;
        renderDetail();
        renderTable();
    });
}

// ─── Filter Dropdowns ────────────────────────────────────────
function populateFilters() {
    const countries = meta?.facets?.countries
        ? Object.entries(meta.facets.countries).sort((a, b) => b[1] - a[1])
        : computeFacet('c');
    const asns = meta?.facets?.asns
        ? Object.entries(meta.facets.asns).sort((a, b) => b[1] - a[1])
        : computeFacet('an');

    const cSel = document.getElementById('inv-filter-country');
    countries.forEach(([v, n]) => {
        const o = document.createElement('option');
        o.value = v; o.textContent = `${v} (${n.toLocaleString()})`;
        cSel.appendChild(o);
    });

    const aSel = document.getElementById('inv-filter-asn');
    asns.slice(0, 40).forEach(([v, n]) => {
        const o = document.createElement('option');
        o.value = v; o.textContent = `${trunc(v, 25)} (${n.toLocaleString()})`;
        aSel.appendChild(o);
    });
}

function computeFacet(key) {
    const c = {};
    allData.forEach(r => { if (r[key]) c[r[key]] = (c[r[key]] || 0) + 1; });
    return Object.entries(c).sort((a, b) => b[1] - a[1]);
}

// ─── Events ──────────────────────────────────────────────────
function bindEvents() {
    let t;
    document.getElementById('inv-search').addEventListener('input', (e) => {
        clearTimeout(t);
        t = setTimeout(() => {
            searchQuery = e.target.value.trim();
            applyFilters(); renderKPIs(); renderTable();
        }, 200);
    });

    ['risk', 'country', 'asn', 'status'].forEach(n => {
        document.getElementById('inv-filter-' + n).addEventListener('change', (e) => {
            filters[n] = e.target.value;
            applyFilters(); renderKPIs(); renderTable();
        });
    });

    document.querySelectorAll('.inv-th').forEach(th => {
        th.addEventListener('click', () => {
            const col = th.dataset.sort;
            if (!col) return;
            if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
            else { sortCol = col; sortDir = 'asc'; }
            applyFilters(); renderSortIndicators(); renderTable();
        });
    });

    document.getElementById('inv-prev').addEventListener('click', () => {
        if (currentPage > 0) { currentPage--; renderTable(); }
    });
    document.getElementById('inv-next').addEventListener('click', () => {
        if (currentPage < Math.ceil(filtered.length / PAGE_SIZE) - 1) { currentPage++; renderTable(); }
    });

    document.getElementById('inv-detail-overlay').addEventListener('click', () => {
        selectedRow = null; renderDetail(); renderTable();
    });

    document.getElementById('inv-reset-filters').addEventListener('click', () => {
        searchQuery = '';
        filters = { risk: 'all', country: 'all', asn: 'all', status: 'all' };
        document.getElementById('inv-search').value = '';
        ['risk', 'country', 'asn', 'status'].forEach(n =>
            document.getElementById('inv-filter-' + n).value = 'all');
        applyFilters(); renderKPIs(); renderTable();
    });
}

// ─── Public: Load ────────────────────────────────────────────
export async function loadInvestigate() {
    const container = document.getElementById('inv-content');
    const loading = document.getElementById('inv-loading');
    const empty = document.getElementById('inv-empty');

    try {
        try { meta = await fetchJSON('investigate_meta.json'); } catch (_) {}

        loading.style.display = '';
        container.style.display = 'none';
        empty.style.display = 'none';

        const data = await fetchJSON('investigate_index.json');
        if (!data || !data.length) {
            loading.style.display = 'none';
            empty.style.display = '';
            return;
        }

        allData = data;
        filtered = data.slice();
        console.log('[Investigate] Loaded ' + allData.length.toLocaleString() + ' domains');

        document.getElementById('inv-total-badge').textContent =
            allData.length.toLocaleString() + ' domains';

        populateFilters();
        renderKPIs();
        renderTable();
        renderSortIndicators();
        bindEvents();

        loading.style.display = 'none';
        container.style.display = '';
    } catch (e) {
        console.log('No investigate data available', e);
        loading.style.display = 'none';
        empty.style.display = '';
    }
}
