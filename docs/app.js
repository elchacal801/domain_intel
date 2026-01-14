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
        // --- 0. Load AI Briefing ---
        try {
            const briefingResp = await fetch('data/daily_briefing.json');
            if (briefingResp.ok) {
                const b = await briefingResp.json();

                document.getElementById('briefing-container').style.display = 'block';
                document.getElementById('briefing-headline').textContent = b.headline || "Daily Intelligence Briefing";
                document.getElementById('briefing-date').textContent = b.date || new Date().toISOString().split('T')[0];
                document.getElementById('briefing-summary').textContent = b.summary || "No summary available.";

                const riskList = document.getElementById('briefing-risks');
                riskList.innerHTML = (b.key_risks || []).map(r => `<li>${r}</li>`).join('');

                const actionList = document.getElementById('briefing-actions');
                actionList.innerHTML = (b.action_items || []).map(a => `<li>${a}</li>`).join('');
            }
        } catch (e) {
            console.log("No briefing found or JSON error", e);
        }

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

        // --- 4. Web Servers ---
        try {
            const serverData = await fetchData('data/web_server_counts.csv');
            const topServers = serverData.slice(0, 8); // Top 8

            const srvCtx = document.getElementById('serverChart').getContext('2d');
            new Chart(srvCtx, {
                type: 'doughnut',
                data: {
                    labels: topServers.map(r => r[0]),
                    datasets: [{
                        data: topServers.map(r => parseInt(r[1])),
                        backgroundColor: [
                            '#238636', '#DA3633', '#8957e5', '#d29922',
                            '#f778ba', '#77bdfb', '#56d364', '#f0883e'
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { position: 'right' }
                    }
                }
            });
        } catch (e) { console.log('No server stats yet'); }

        // --- 5. AI Classifications ---
        try {
            const aiData = await fetchData('data/ai_classifications.csv');
            // Group by category
            const aiCounts = {};
            aiData.forEach(row => {
                const cat = row[1] || 'Unknown';
                aiCounts[cat] = (aiCounts[cat] || 0) + 1;
            });

            const aiLabels = Object.keys(aiCounts);
            const aiValues = Object.values(aiCounts);

            const aiCtx = document.getElementById('aiChart').getContext('2d');
            new Chart(aiCtx, {
                type: 'doughnut',
                data: {
                    labels: aiLabels,
                    datasets: [{
                        data: aiValues,
                        backgroundColor: [
                            '#DA3633', '#d29922', '#1f6feb', '#238636', '#8957e5'
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { position: 'right' }
                    }
                }
            });
        } catch (e) { console.log('No AI stats yet'); }

        // --- 6. Visual Forensics ---
        try {
            const visualResp = await fetch('data/visual_clusters.json');
            if (visualResp.ok) {
                const clusters = await visualResp.json();
                if (clusters.length > 0) {
                    document.getElementById('visual-intel-container').style.display = 'block';
                    const gallery = document.getElementById('cluster-gallery');

                    // Take top 6 largest clusters
                    clusters.slice(0, 6).forEach(cluster => {
                        const count = cluster.count;
                        const mainDomain = cluster.domains[0];
                        // Use screenshot of the first domain in cluster
                        const imgPath = `data/screenshots/${mainDomain}.jpg`;

                        const card = document.createElement('div');
                        card.className = 'cluster-card';

                        // Domain list HTML
                        const domainList = cluster.domains.map(d =>
                            `<a href="http://${d}" target="_blank" class="domain-link">${d}</a>`
                        ).join('');

                        card.innerHTML = `
                            <img src="${imgPath}" class="cluster-img" onerror="this.src='https://via.placeholder.com/280x160?text=Screenshot+Missing'">
                            <div class="cluster-info">
                                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                                    <span class="cluster-count">${count} Domains</span>
                                    <span style="font-size:0.8em; color:#8b949e;">Visual Match</span>
                                </div>
                                <div class="cluster-domains">
                                    ${domainList}
                                </div>
                            </div>
                        `;
                        gallery.appendChild(card);
                    });
                }
            }
        } catch (e) { console.log('No visual clusters yet', e); }

    } catch (e) {
        console.error("Error loading data:", e);
    }
}

// Chart.js Global Defaults
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#30363d';

initDashboard();
