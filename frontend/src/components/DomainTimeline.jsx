/**
 * DomainTimeline — Vertical timeline showing temporal events for a domain.
 * Extracts dates from domain record fields and displays them chronologically.
 */

function parseDate(val) {
    if (!val || val === 'N/A' || val === '') return null;
    const d = new Date(val);
    return isNaN(d.getTime()) ? null : d;
}

function formatDate(d) {
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

function daysAgo(d) {
    const diff = Math.floor((Date.now() - d.getTime()) / 86400000);
    if (diff === 0) return 'Today';
    if (diff === 1) return 'Yesterday';
    if (diff < 0) return `In ${Math.abs(diff)} days`;
    return `${diff} days ago`;
}

const EVENT_COLORS = {
    created: '#5b8abf',
    expires: '#c98a5a',
    scan: '#6aab7b',
    risk: '#ef4444',
    match: '#8b7ec7',
};

export default function DomainTimeline({ data }) {
    if (!data) return null;

    // Extract temporal events from domain record
    const events = [];

    const created = parseDate(data.creation_date || data.whois_creation_date);
    if (created) {
        events.push({ date: created, label: 'Domain Created', type: 'created', detail: formatDate(created) });
    }

    const expires = parseDate(data.whois_expiration_date || data.expiry_date);
    if (expires) {
        const isFuture = expires > new Date();
        events.push({
            date: expires, label: isFuture ? 'Registration Expires' : 'Registration Expired',
            type: 'expires', detail: formatDate(expires),
        });
    }

    const vtScan = parseDate(data.vt_last_analysis);
    if (vtScan) {
        events.push({ date: vtScan, label: 'VirusTotal Last Scan', type: 'scan', detail: formatDate(vtScan) });
    }

    // Risk score as a "snapshot" event (today)
    if (data.risk_score != null && data.risk_score > 0) {
        events.push({
            date: new Date(), label: 'Current Risk Assessment',
            type: 'risk', detail: `Score: ${data.risk_score} (${data.risk_level})`,
        });
    }

    // Fingerprint match (today if present)
    if (data.matches?.length > 0) {
        events.push({
            date: new Date(), label: `${data.matches.length} Fingerprint Match${data.matches.length > 1 ? 'es' : ''}`,
            type: 'match', detail: data.matches.map(m => m.fp_id).join(', '),
        });
    }

    if (events.length === 0) return null;

    // Sort chronologically
    events.sort((a, b) => a.date - b.date);

    return (
        <div className="relative pl-6 space-y-0">
            {/* Vertical line */}
            <div className="absolute left-[11px] top-2 bottom-2 w-px" style={{ background: 'var(--border-subtle)' }} />

            {events.map((evt, i) => (
                <div key={i} className="relative flex items-start gap-3 py-2.5 group">
                    {/* Dot */}
                    <div className="absolute left-[-13px] top-3 flex items-center justify-center">
                        <div className="h-2.5 w-2.5 rounded-full ring-2 transition-transform group-hover:scale-125"
                            style={{
                                background: EVENT_COLORS[evt.type] || '#888',
                                ringColor: 'var(--bg-surface-raised)',
                                boxShadow: `0 0 6px ${EVENT_COLORS[evt.type]}40`,
                            }}
                        />
                    </div>

                    {/* Content */}
                    <div className="flex-1 ml-1">
                        <div className="flex items-center gap-2">
                            <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>
                                {evt.label}
                            </span>
                            <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
                                {daysAgo(evt.date)}
                            </span>
                        </div>
                        <div className="text-[11px] font-mono mt-0.5" style={{ color: 'var(--text-secondary)' }}>
                            {evt.detail}
                        </div>
                    </div>
                </div>
            ))}
        </div>
    );
}
