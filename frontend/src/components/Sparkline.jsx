/**
 * Sparkline — tiny SVG line chart for KPI trend visualization.
 * Pure SVG, no dependencies.
 * 
 * Props:
 *   data: number[] — array of values
 *   width: number (default 80)
 *   height: number (default 24)
 *   color: string (default '#888')
 *   strokeWidth: number (default 1.5)
 */
export default function Sparkline({ data = [], width = 80, height = 24, color = '#888', strokeWidth = 1.5 }) {
    if (!data || data.length < 2) return null;

    const min = Math.min(...data);
    const max = Math.max(...data);
    const range = max - min || 1;
    const padding = 2;
    const innerW = width - padding * 2;
    const innerH = height - padding * 2;

    const points = data.map((v, i) => {
        const x = padding + (i / (data.length - 1)) * innerW;
        const y = padding + innerH - ((v - min) / range) * innerH;
        return `${x},${y}`;
    }).join(' ');

    // Gradient fill area
    const firstX = padding;
    const lastX = padding + innerW;
    const areaPoints = `${firstX},${height} ${points} ${lastX},${height}`;

    return (
        <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="inline-block">
            <defs>
                <linearGradient id={`spark-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={color} stopOpacity="0.2" />
                    <stop offset="100%" stopColor={color} stopOpacity="0" />
                </linearGradient>
            </defs>
            <polygon
                points={areaPoints}
                fill={`url(#spark-${color.replace('#', '')})`}
            />
            <polyline
                points={points}
                fill="none"
                stroke={color}
                strokeWidth={strokeWidth}
                strokeLinecap="round"
                strokeLinejoin="round"
            />
        </svg>
    );
}
