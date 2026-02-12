/**
 * main.js — Domain Intelligence Dashboard
 * Entry point: initializes navigation, loads data, and renders all charts.
 */
import './style.css';
import { fetchCSV, fetchJSON, truncate, countColumn, topEntries } from './data.js';
import { horizontalBar, verticalBar, verticalBarMulti, doughnut, lineArea, PALETTE } from './charts.js';

// ─── Navigation ───────────────────────────────────────────────
function initNavigation() {
    const tabs = document.querySelectorAll('.nav-tab');
    const views = document.querySelectorAll('.view');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.view;
            tabs.forEach(t => t.classList.remove('active'));
            views.forEach(v => v.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById(`view-${target}`).classList.add('active');
        });
    });
}

// ─── Status Indicator ─────────────────────────────────────────
function setStatus(state, text) {
    const dot = document.getElementById('status-dot');
    const label = document.getElementById('status-text');
    dot.className = `pulse-dot ${state}`;
    label.textContent = text;
}

// ─── Load AI Briefing ─────────────────────────────────────────
async function loadBriefing() {
    try {
        const b = await fetchJSON('daily_briefing.json');
        const card = document.getElementById('briefing-card');
        card.style.display = 'block';
        document.getElementById('briefing-headline').textContent = b.headline || 'Daily Intelligence Briefing';
        document.getElementById('briefing-date').textContent = b.date || new Date().toISOString().split('T')[0];
        document.getElementById('briefing-summary').textContent = b.summary || b.executive_summary || 'No summary available.';
        document.getElementById('briefing-risks').innerHTML = (b.key_risks || []).map(r => `<li>${r}</li>`).join('');
        document.getElementById('briefing-actions').innerHTML = (b.action_items || []).map(a => `<li>${a}</li>`).join('');
    } catch (e) { console.log('No briefing data', e); }
}

// ─── Load History & Growth Chart ──────────────────────────────
async function loadHistory() {
    try {
        const data = await fetchJSON('history.json');
        if (!data.length) return;

        const latest = data[data.length - 1];
        const prev = data.length > 1 ? data[data.length - 2] : null;
        const newCount = prev ? latest.total - prev.total : 0;

        // KPI updates
        document.getElementById('kpi-total').textContent = latest.total?.toLocaleString() || '—';
        document.getElementById('kpi-live').textContent = latest.live?.toLocaleString() || '—';
        document.getElementById('kpi-new').textContent = newCount > 0 ? `+${newCount}` : '0';

        // Growth chart
        lineArea('growthChart', data.map(d => d.date), [
            { label: 'Total Domains', data: data.map(d => d.total), color: 'rgba(139,148,158,0.8)' },
            { label: 'Live Threats', data: data.map(d => d.live), color: PALETTE.green },
        ]);
    } catch (e) { console.log('No history data', e); }
}

// ─── Load Overview Charts ─────────────────────────────────────
async function loadOverviewCharts() {
    // Registrars
    try {
        const regData = await fetchCSV('domain_registrars.csv');
        const regCounts = countColumn(regData, 1);
        const sorted = topEntries(regCounts, 10);
        if (sorted.length) {
            horizontalBar('registrarChart', sorted.map(x => truncate(x[0], 22)), sorted.map(x => x[1]), PALETTE.orange);
        }
    } catch (e) { console.log('No registrar data', e); }

    // Web Servers
    try {
        const serverData = await fetchCSV('web_server_counts.csv');
        const top = serverData.slice(0, 8);
        if (top.length) {
            doughnut('serverChart', top.map(r => r[0]), top.map(r => parseInt(r[1])));
        }
    } catch (e) { console.log('No server data', e); }
}

// ─── Load Threat Charts ───────────────────────────────────────
async function loadThreatCharts() {
    // OpenClaw
    try {
        const ocData = await fetchCSV('openclaw_exposed.csv', true);
        if (ocData.length) {
            document.getElementById('openclaw-card').style.display = 'block';
            const riskCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
            ocData.forEach(r => {
                const lvl = (r.risk_level || 'MEDIUM').toUpperCase();
                riskCounts[lvl] = (riskCounts[lvl] || 0) + 1;
            });
            document.getElementById('oc-total').textContent = ocData.length;
            document.getElementById('oc-critical').textContent = riskCounts.CRITICAL;
            doughnut('openclawChart',
                Object.keys(riskCounts), Object.values(riskCounts),
                [PALETTE.red, PALETTE.orange, 'rgba(210,153,34,0.6)', PALETTE.green]
            );
        }
    } catch (e) { console.log('No OpenClaw data', e); }

    // AI Classifications
    try {
        const aiData = await fetchCSV('ai_classifications.csv');
        const aiCounts = countColumn(aiData, 1);
        const labels = Object.keys(aiCounts);
        if (labels.length) {
            doughnut('aiChart', labels, Object.values(aiCounts));
        }
    } catch (e) { console.log('No AI classification data', e); }

    // Risk Signals
    try {
        const riskData = await fetchCSV('risk_counts.csv');
        if (riskData.length) {
            const totalRisk = riskData.reduce((acc, r) => acc + parseInt(r[1] || 0), 0);
            document.getElementById('kpi-risk').textContent = totalRisk.toLocaleString();
            horizontalBar('riskChart',
                riskData.map(r => r[0].replace('HighRisk:', '')),
                riskData.map(r => parseInt(r[1])),
                PALETTE.red
            );
        }
    } catch (e) { console.log('No risk data', e); }

    // Keywords
    try {
        const keyData = await fetchCSV('title_keyword_counts.csv');
        const top = keyData.slice(0, 15);
        if (top.length) {
            verticalBar('keywordChart', top.map(r => r[0]), top.map(r => parseInt(r[1])), PALETTE.purple);
        }
    } catch (e) { console.log('No keyword data', e); }

    // Visual Forensics
    try {
        const clusters = await fetchJSON('visual_clusters.json');
        if (clusters.length) {
            document.getElementById('visual-card').style.display = 'block';
            const gallery = document.getElementById('cluster-gallery');
            clusters.slice(0, 6).forEach(cluster => {
                const card = document.createElement('div');
                card.className = 'cluster-card';
                const imgPath = `data/screenshots/${cluster.domains[0]}.jpg`;
                card.innerHTML = `
          <img src="${imgPath}" class="cluster-img" onerror="this.src='https://via.placeholder.com/280x160/0a0e14/5d6b7a?text=No+Screenshot'">
          <div class="cluster-info">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
              <span class="cluster-count">${cluster.count} Domains</span>
              <span style="font-size:0.75rem;color:var(--text-muted);">Visual Match</span>
            </div>
            <div class="cluster-domains">
              ${cluster.domains.map(d => `<a href="http://${d}" target="_blank" class="domain-link">${d}</a>`).join('')}
            </div>
          </div>`;
                gallery.appendChild(card);
            });
        }
    } catch (e) { console.log('No visual clusters', e); }
}

// ─── Load Infrastructure Charts ───────────────────────────────
async function loadInfraCharts() {
    // ASN
    try {
        const asnData = await fetchCSV('asn_counts.csv');
        const top = asnData.slice(0, 10);
        if (top.length) {
            horizontalBar('asnChart',
                top.map(r => `AS${r[0]} (${truncate(r[1], 15)})`),
                top.map(r => parseInt(r[2])),
                PALETTE.green
            );
        }
    } catch (e) { console.log('No ASN data', e); }

    // MX
    try {
        const mxData = await fetchCSV('mx_counts.csv');
        const top = mxData.slice(0, 10);
        if (top.length) {
            horizontalBar('mxChart', top.map(r => truncate(r[0], 25)), top.map(r => parseInt(r[1])), PALETTE.blue);
        }
    } catch (e) { console.log('No MX data', e); }

    // Shodan (Ports + Vulns)
    try {
        const shodanData = await fetchCSV('shodan_intelligence.csv', true);
        const portCounts = {};
        const vulnCounts = {};
        shodanData.forEach(row => {
            if (row.ports) {
                row.ports.split(';').forEach(p => {
                    const port = p.trim();
                    if (port && !isNaN(port) && parseInt(port) > 0 && parseInt(port) <= 65535) {
                        portCounts[port] = (portCounts[port] || 0) + 1;
                    }
                });
            }
            if (row.vulns) {
                row.vulns.split(';').forEach(v => {
                    if (v.startsWith('CVE')) vulnCounts[v] = (vulnCounts[v] || 0) + 1;
                });
            }
        });

        const sortedPorts = topEntries(portCounts, 10);
        if (sortedPorts.length) {
            verticalBar('portChart', sortedPorts.map(x => x[0]), sortedPorts.map(x => x[1]), PALETTE.orange);
        }

        const sortedVulns = topEntries(vulnCounts, 10);
        if (sortedVulns.length) {
            horizontalBar('vulnChart', sortedVulns.map(x => x[0]), sortedVulns.map(x => x[1]), PALETTE.red);
        }
    } catch (e) { console.log('No Shodan data', e); }

    // HTTP Status
    try {
        const statusData = await fetchCSV('http_status_counts.csv');
        if (statusData.length) {
            const colors = statusData.map(r => {
                const s = r[0];
                if (s.startsWith('2')) return PALETTE.green;
                if (s.startsWith('3')) return PALETTE.blue;
                if (s.startsWith('4')) return PALETTE.orange;
                return PALETTE.red;
            });
            verticalBarMulti('httpStatusChart', statusData.map(r => r[0]), statusData.map(r => parseInt(r[1])), colors);
        }
    } catch (e) { console.log('No HTTP status data', e); }
}

// ─── Load Campaign Data ───────────────────────────────────────
async function loadCampaigns() {
    try {
        const campData = await fetchCSV('campaign_hunt_history.csv', true);
        if (!campData.length) return;

        // Hide empty state, show data panels
        document.getElementById('campaign-empty').style.display = 'none';
        document.getElementById('campaign-kpis').style.display = '';
        document.getElementById('campaign-timeline-card').style.display = '';
        document.getElementById('campaign-table-card').style.display = '';

        // Sort by first_seen descending
        campData.sort((a, b) => new Date(b.first_seen) - new Date(a.first_seen));

        // KPIs
        const uniqueIPs = new Set(campData.map(r => r.ip));
        const uniqueCountries = new Set(campData.map(r => r.country).filter(Boolean));
        const uniqueQueries = new Set(campData.map(r => r.query).filter(Boolean));
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        const recentHits = campData.filter(r => new Date(r.first_seen) >= sevenDaysAgo);

        document.getElementById('camp-total').textContent = uniqueIPs.size;
        document.getElementById('camp-new').textContent = recentHits.length;
        document.getElementById('camp-countries').textContent = uniqueCountries.size;
        document.getElementById('camp-queries').textContent = uniqueQueries.size;
        document.getElementById('camp-count-badge').textContent = `${campData.length} hits`;

        // Timeline chart — group by date
        const dateCounts = {};
        campData.forEach(r => {
            const d = r.first_seen.split(' ')[0]; // YYYY-MM-DD
            dateCounts[d] = (dateCounts[d] || 0) + 1;
        });
        const sortedDates = Object.keys(dateCounts).sort();
        if (sortedDates.length) {
            verticalBar('campaignChart', sortedDates, sortedDates.map(d => dateCounts[d]), PALETTE.red);
        }

        // Table
        const tbody = document.getElementById('campaign-tbody');
        campData.forEach(r => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${r.first_seen || '—'}</td>
                <td>${r.ip || '—'}</td>
                <td>${r.org || 'n/a'}</td>
                <td>${r.country || 'n/a'}</td>
                <td title="${r.query || ''}">${truncate(r.query || '', 50)}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) { console.log('No campaign data', e); }
}

// ─── Main Entry ───────────────────────────────────────────────
async function init() {
    setStatus('loading', 'Loading data...');
    initNavigation();

    try {
        // Load all data sections in parallel
        await Promise.all([
            loadBriefing(),
            loadHistory(),
            loadOverviewCharts(),
            loadThreatCharts(),
            loadInfraCharts(),
            loadCampaigns(),
        ]);

        setStatus('', `Updated ${new Date().toLocaleDateString()}`);
    } catch (e) {
        console.error('Dashboard init error:', e);
        setStatus('error', 'Error loading data');
    }
}

init();
