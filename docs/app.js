// app.js

async function fetchData(url) {
    const response = await fetch(url);
    const data = await response.text();
    const rows = data.split('\n').filter(r => r.trim() !== '');
    const header = rows.shift(); // Skip header
    return rows.map(row => parseCSVRow(row));
}

// Robust CSV parser to handle quoted strings with commas (e.g. "Company, Inc.")
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

    // Clean up quotes
    return result.map(val => {
        val = val.trim();
        if (val.startsWith('"') && val.endsWith('"')) {
            return val.slice(1, -1);
        }
        return val;
    });
}

function truncate(str, n) {
    return (str.length > n) ? str.substr(0, n - 1) + '...' : str;
}

async function initDashboard() {
    // Set updated time
    document.getElementById('last-updated').textContent = `Updated: ${new Date().toLocaleDateString()}`;

    try {
        // --- 1. Load ASN Counts ---
        const asnData = await fetchData('data/asn_counts.csv');
        // Format: asn, asn_name, domain_count
        const topASNs = asnData.slice(0, 10);

        // Update Total Stats
        // Approximation: Sum of top 50 or similar, but for now we'll sum what we loaded
        // Real total is simpler if we had a meta file, but we'll fetch others.

        // Render ASN Chart
        const asnCtx = document.getElementById('asnChart').getContext('2d');
        new Chart(asnCtx, {
            type: 'bar',
            data: {
                labels: topASNs.map(r => `AS${r[0]} (${truncate(r[1], 15)})`),
                datasets: [{
                    label: 'Domains Hosted',
                    data: topASNs.map(r => parseInt(r[2])),
                    backgroundColor: 'rgba(46, 160, 67, 0.7)',
                    borderColor: '#2ea043',
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { grid: { color: '#30363d' } },
                    y: { grid: { display: false } }
                }
            }
        });

        document.getElementById('stat-total-asn').textContent = asnData.length;

        // --- 2. Load MX Counts ---
        const mxData = await fetchData('data/mx_counts.csv');
        // Format: mx_host, domain_count, primary_asn
        const topMX = mxData.slice(0, 10);

        const mxCtx = document.getElementById('mxChart').getContext('2d');
        new Chart(mxCtx, {
            type: 'bar',
            data: {
                labels: topMX.map(r => truncate(r[0], 25)),
                datasets: [{
                    label: 'Domains Using MX',
                    data: topMX.map(r => parseInt(r[1])),
                    backgroundColor: 'rgba(56, 139, 253, 0.7)',
                    borderColor: '#388bfd',
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { grid: { color: '#30363d' } },
                    y: { grid: { display: false } }
                }
            }
        });

        document.getElementById('stat-top-mx').textContent = topMX[0][0];

        // --- 3. Total Domains (Approximation from DEA list) ---
        // We'll fetch the DEA Enriched to count lines? Or just sum MX counts?
        // Let's sum MX counts for a rough "Total Enriched"
        const totalDomains = mxData.reduce((acc, curr) => acc + parseInt(curr[1] || 0), 0);
        document.getElementById('stat-total-dea').textContent = totalDomains.toLocaleString();

    } catch (e) {
        console.error("Error loading data:", e);
    }
}

// Chart.js Global Defaults
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#30363d';

initDashboard();
