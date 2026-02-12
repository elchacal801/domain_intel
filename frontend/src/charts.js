/**
 * charts.js — Chart.js configuration and factory methods
 * Provides themed chart presets and a unified creation API.
 */
import { Chart, registerables } from 'chart.js';

// Register all Chart.js components
Chart.register(...registerables);

// Global theme defaults
Chart.defaults.color = '#8b97a8';
Chart.defaults.borderColor = '#1e2d3d';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 12;
Chart.defaults.plugins.legend.labels.padding = 12;
Chart.defaults.plugins.legend.labels.usePointStyle = true;

// Color Palette
const PALETTE = {
    blue: 'rgba(88, 166, 255, 0.8)',
    green: 'rgba(63, 185, 80, 0.8)',
    red: 'rgba(248, 81, 73, 0.8)',
    orange: 'rgba(210, 153, 34, 0.8)',
    purple: 'rgba(163, 113, 247, 0.8)',
    pink: 'rgba(247, 120, 186, 0.8)',
    cyan: 'rgba(86, 211, 100, 0.8)',
    teal: 'rgba(63, 185, 150, 0.8)',
};

const MULTI_COLORS = [
    PALETTE.blue, PALETTE.red, PALETTE.purple, PALETTE.orange,
    PALETTE.green, PALETTE.pink, PALETTE.cyan, PALETTE.teal,
    'rgba(139,148,158,0.7)', 'rgba(121,184,255,0.7)',
];

// Common options fragments
const HORIZONTAL_BAR_OPTS = {
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
        x: { grid: { color: '#1e2d3d' }, ticks: { font: { size: 11 } } },
        y: { grid: { display: false }, ticks: { font: { size: 11 } } },
    },
};

const VERTICAL_BAR_OPTS = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
        x: { grid: { display: false }, ticks: { font: { size: 11 } } },
        y: { grid: { color: '#1e2d3d' }, ticks: { font: { size: 11 } } },
    },
};

const DOUGHNUT_OPTS = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
        legend: { position: 'right', labels: { font: { size: 11 }, padding: 8 } },
    },
};

const LINE_OPTS = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
        legend: { position: 'top', labels: { font: { size: 11 } } },
    },
    scales: {
        y: { grid: { color: '#1e2d3d' } },
        x: { grid: { display: false } },
    },
};

/**
 * Create a horizontal bar chart.
 */
export function horizontalBar(canvasId, labels, data, color = PALETTE.green) {
    const ctx = document.getElementById(canvasId)?.getContext('2d');
    if (!ctx) return null;
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{ data, backgroundColor: color, borderWidth: 0, borderRadius: 3 }],
        },
        options: { ...HORIZONTAL_BAR_OPTS },
    });
}

/**
 * Create a vertical bar chart.
 */
export function verticalBar(canvasId, labels, data, color = PALETTE.purple) {
    const ctx = document.getElementById(canvasId)?.getContext('2d');
    if (!ctx) return null;
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{ data, backgroundColor: color, borderWidth: 0, borderRadius: 3 }],
        },
        options: { ...VERTICAL_BAR_OPTS },
    });
}

/**
 * Create a vertical bar chart with per-bar colors.
 */
export function verticalBarMulti(canvasId, labels, data, colors) {
    const ctx = document.getElementById(canvasId)?.getContext('2d');
    if (!ctx) return null;
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{ data, backgroundColor: colors, borderWidth: 0, borderRadius: 3 }],
        },
        options: { ...VERTICAL_BAR_OPTS },
    });
}

/**
 * Create a doughnut chart.
 */
export function doughnut(canvasId, labels, data, colors = MULTI_COLORS) {
    const ctx = document.getElementById(canvasId)?.getContext('2d');
    if (!ctx) return null;
    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{ data, backgroundColor: colors.slice(0, labels.length), borderWidth: 0 }],
        },
        options: { ...DOUGHNUT_OPTS },
    });
}

/**
 * Create a multi-line area chart.
 * @param {Array<{label, data, color}>} series
 */
export function lineArea(canvasId, labels, series) {
    const ctx = document.getElementById(canvasId)?.getContext('2d');
    if (!ctx) return null;
    return new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: series.map(s => ({
                label: s.label,
                data: s.data,
                borderColor: s.color,
                backgroundColor: s.color.replace('0.8', '0.15'),
                fill: true,
                tension: 0.35,
                pointRadius: 2,
                pointHoverRadius: 5,
                borderWidth: 2,
            })),
        },
        options: { ...LINE_OPTS },
    });
}

export { PALETTE, MULTI_COLORS };
