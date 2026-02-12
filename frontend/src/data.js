/**
 * data.js — Data loading utilities
 * Handles CSV parsing, JSON loading, and data directory resolution.
 */

// In prod build (GitHub Pages), data lives alongside
// the built assets. During dev, we proxy to ../docs/
const DATA_BASE = import.meta.env.DEV ? '/data' : './data';
const HISTORY_URL = import.meta.env.DEV ? '/history.json' : './history.json';

/**
 * Parse a single CSV row, handling quoted fields with commas.
 */
function parseCSVRow(str) {
    const result = [];
    let current = '';
    let inQuote = false;

    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        if (char === '"') {
            inQuote = !inQuote;
        } else if (char === ',' && !inQuote) {
            result.push(current);
            current = '';
        } else {
            current += char;
        }
    }
    result.push(current);
    return result.map(v => v.trim().replace(/^"|"$/g, ''));
}

/**
 * Fetch and parse a CSV file.
 * @param {string} filename — Filename relative to data dir (e.g. 'asn_counts.csv')
 * @param {boolean} asObjects — If true, returns array of objects keyed by header row
 * @returns {Promise<Array>}
 */
export async function fetchCSV(filename, asObjects = false) {
    const url = `${DATA_BASE}/${filename}`;
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`Failed to load ${url}: ${resp.status}`);

    const text = await resp.text();
    const rows = text.split('\n').filter(r => r.trim() !== '');
    const header = rows.shift();

    if (asObjects && header) {
        const headers = parseCSVRow(header);
        return rows.map(row => {
            const values = parseCSVRow(row);
            const obj = {};
            headers.forEach((h, i) => { obj[h.trim()] = values[i] || ''; });
            return obj;
        });
    }

    return rows.map(row => parseCSVRow(row));
}

/**
 * Fetch a JSON file.
 * @param {string} filename — Filename relative to data dir
 * @returns {Promise<any>}
 */
export async function fetchJSON(filename) {
    const url = filename === 'history.json' ? HISTORY_URL : `${DATA_BASE}/${filename}`;
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`Failed to load ${url}: ${resp.status}`);
    return resp.json();
}

/**
 * Truncate a string, adding ellipsis if needed.
 */
export function truncate(str, n) {
    return str.length > n ? str.substring(0, n - 1) + '…' : str;
}

/**
 * Count occurrences of values in a column.
 * @param {Array<Array>} rows — Parsed CSV rows
 * @param {number} col — Column index
 * @returns {Object} — { value: count }
 */
export function countColumn(rows, col) {
    const counts = {};
    rows.forEach(row => {
        const val = (row[col] || '').trim();
        if (val) counts[val] = (counts[val] || 0) + 1;
    });
    return counts;
}

/**
 * Sort an object's entries by value descending and take top N.
 * @returns {Array<[string, number]>}
 */
export function topEntries(obj, n = 10) {
    return Object.entries(obj)
        .sort((a, b) => b[1] - a[1])
        .slice(0, n);
}
