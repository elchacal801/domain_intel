import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, FileText, AlertTriangle, Target, Radio, ChevronDown, ChevronRight, Calendar, BarChart3 } from 'lucide-react';
import Section from '@/components/Section';
import ConfidenceBadge from '@/components/ConfidenceBadge';

/* ---- Priority tag styling ---- */
function PriorityTag({ text }) {
    const lower = text.toLowerCase();
    let cls = 'priority-medium';
    if (lower.includes('immediate')) cls = 'priority-immediate';
    else if (lower.includes('urgent')) cls = 'priority-urgent';
    else if (lower.includes('high')) cls = 'priority-high';
    else if (lower.includes('tactical')) cls = 'priority-tactical';
    else if (lower.includes('strategic')) cls = 'priority-strategic';

    return (
        <span className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${cls}`}
            style={{ background: 'rgba(255,255,255,0.03)' }}
        >
            {text}
        </span>
    );
}

/** Parse the leading priority from an action item like "IMMEDIATE: Do something" */
function parseAction(text) {
    const match = text.match(/^(IMMEDIATE|URGENT|HIGH PRIORITY|HIGH|MEDIUM PRIORITY|MEDIUM|TACTICAL|STRATEGIC):\s*/i);
    if (!match) return { priority: null, body: text };
    return { priority: match[1], body: text.slice(match[0].length) };
}

/* ---- Highlight intelligence confidence language ---- */
function highlightConfidence(text) {
    if (!text) return text;
    const patterns = [
        'Highly Likely', 'Likely', 'Roughly Even Chance', 'Unlikely', 'Highly Unlikely',
        'High confidence', 'Medium-High confidence', 'Medium confidence', 'Low confidence',
        'High Confidence', 'Medium Confidence',
    ];
    let result = text;
    for (const p of patterns) {
        result = result.replaceAll(p, `«${p}»`);
    }
    // Split on markers and render
    const parts = result.split(/«|»/);
    return parts.map((part, i) => {
        if (patterns.includes(part)) {
            const isHigh = /high/i.test(part);
            const isMed = /medium|even/i.test(part);
            const color = isHigh ? 'text-green-400' : isMed ? 'text-yellow-400' : 'text-red-400';
            return <span key={i} className={`font-semibold ${color}`}>{part}</span>;
        }
        return part;
    });
}

export default function BriefingView() {
    const navigate = useNavigate();
    const [briefing, setBriefing] = useState(null);
    const [history, setHistory] = useState([]);
    const [selectedDate, setSelectedDate] = useState(null);
    const [loading, setLoading] = useState(true);

    // Load current + history
    useEffect(() => {
        async function load() {
            try {
                const [briefRes, histRes] = await Promise.all([
                    fetch('./data/daily_briefing.json').then(r => r.ok ? r.json() : null),
                    fetch('./data/briefing_history.json').then(r => r.ok ? r.json() : null),
                ]);
                setBriefing(briefRes);
                setHistory(histRes?.dates || histRes || []);
            } catch (e) {
                console.error('Failed to load briefing:', e);
            } finally {
                setLoading(false);
            }
        }
        load();
    }, []);

    async function loadHistorical(date) {
        setSelectedDate(date);
        setLoading(true);
        try {
            const res = await fetch(`./data/briefings/briefing_${date}.json`);
            if (res.ok) setBriefing(await res.json());
        } catch (e) {
            console.error('Failed to load briefing:', e);
        } finally {
            setLoading(false);
        }
    }

    if (loading) {
        return (
            <div className="flex h-80 items-center justify-center">
                <div className="flex flex-col items-center gap-3">
                    <div className="h-7 w-7 animate-spin rounded-full border-2 border-white/10 border-t-white/50" />
                    <span className="text-xs text-text-muted">Loading intel briefing…</span>
                </div>
            </div>
        );
    }

    if (!briefing) {
        return (
            <div className="flex h-80 flex-col items-center justify-center gap-3">
                <FileText className="h-8 w-8 text-white/10" />
                <p className="text-sm text-text-muted">No briefing data available.</p>
            </div>
        );
    }

    const actions = (briefing.action_items || []).map(parseAction);

    return (
        <div className="mx-auto max-w-4xl space-y-5 animate-fade-in">
            {/* Classification Banner */}
            <div className="briefing-classification">
                UNCLASSIFIED // Domain Intelligence Briefing
            </div>

            {/* Header */}
            <div className="glass-card p-5">
                <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                            <Shield className="h-4 w-4 text-white/40" />
                            <span className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">
                                Daily Intelligence Briefing
                            </span>
                            <span className="text-[10px] text-text-muted">—</span>
                            <span className="text-[10px] font-mono text-text-secondary">{briefing.date}</span>
                        </div>
                        <h1 className="text-lg font-bold leading-snug text-text-primary">
                            {briefing.headline}
                        </h1>
                    </div>

                    {/* Date selector */}
                    {history.length > 0 && (
                        <select
                            value={selectedDate || briefing.date}
                            onChange={e => loadHistorical(e.target.value)}
                            className="rounded-md border border-border-subtle bg-[#0a0a0a] px-2 py-1.5 text-xs text-text-secondary outline-none focus:border-white/15"
                        >
                            {(Array.isArray(history) ? history : []).map(d => {
                                const date = typeof d === 'string' ? d : d.date;
                                return <option key={date} value={date}>{date}</option>;
                            })}
                        </select>
                    )}
                </div>
            </div>

            {/* Executive Summary (BLUF) */}
            <div className="glass-card p-5">
                <div className="flex items-center gap-2 mb-3">
                    <Target className="h-3.5 w-3.5 text-white/30" />
                    <h2 className="text-[10px] font-bold uppercase tracking-widest text-text-muted">
                        Bottom Line Up Front
                    </h2>
                </div>
                <p className="text-sm leading-relaxed text-text-secondary">
                    {highlightConfidence(briefing.executive_summary || briefing.summary)}
                </p>
            </div>

            {/* Strategic Assessment */}
            {briefing.strategic_assessment && (
                <Section title="Strategic Assessment" icon={<BarChart3 className="h-3.5 w-3.5 text-white/30" />} accentColor="rgba(255,255,255,0.08)" defaultOpen={false}>
                    <p className="text-xs leading-relaxed text-text-secondary">
                        {highlightConfidence(briefing.strategic_assessment)}
                    </p>
                </Section>
            )}

            {/* Operational Intelligence */}
            {briefing.operational_intelligence && (
                <Section title="Operational Intelligence" icon={<Radio className="h-3.5 w-3.5 text-white/30" />} accentColor="rgba(255,255,255,0.08)" defaultOpen={false}>
                    <p className="text-xs leading-relaxed text-text-secondary">
                        {highlightConfidence(briefing.operational_intelligence)}
                    </p>
                </Section>
            )}

            {/* Campaign Highlights */}
            {briefing.campaign_highlights && (
                <Section title="Campaign Highlights" icon={<Target className="h-3.5 w-3.5 text-white/30" />} accentColor="rgba(255,255,255,0.08)" defaultOpen={false}>
                    <p className="text-xs leading-relaxed text-text-secondary">
                        {highlightConfidence(briefing.campaign_highlights)}
                    </p>
                </Section>
            )}

            {/* Risk Signal Analysis */}
            {briefing.risk_signal_analysis && (
                <Section title="Risk Signal Analysis" icon={<BarChart3 className="h-3.5 w-3.5 text-white/30" />} accentColor="rgba(255,255,255,0.08)" defaultOpen={false}>
                    <p className="text-xs leading-relaxed text-text-secondary">
                        {highlightConfidence(briefing.risk_signal_analysis)}
                    </p>
                </Section>
            )}

            {/* Key Risks */}
            {briefing.key_risks?.length > 0 && (
                <Section title={`Key Risks (${briefing.key_risks.length})`} icon={<AlertTriangle className="h-3.5 w-3.5 text-red-400/50" />} accentColor="rgba(239,68,68,0.15)">
                    <div className="space-y-2">
                        {briefing.key_risks.map((risk, i) => (
                            <div key={i} className="flex gap-3 rounded-lg bg-[#0a0a0a] border border-border-subtle p-3">
                                <span className="shrink-0 flex h-5 w-5 items-center justify-center rounded-full bg-red-500/10 text-[10px] font-bold text-red-400">
                                    {i + 1}
                                </span>
                                <p className="text-xs leading-relaxed text-text-secondary">{risk}</p>
                            </div>
                        ))}
                    </div>
                </Section>
            )}

            {/* Action Items */}
            {actions.length > 0 && (
                <Section title={`Action Items (${actions.length})`} icon={<Target className="h-3.5 w-3.5 text-white/30" />} accentColor="rgba(255,255,255,0.08)">
                    <div className="space-y-2">
                        {actions.map((item, i) => (
                            <div key={i} className="flex gap-3 rounded-lg bg-[#0a0a0a] border border-border-subtle p-3">
                                {item.priority && <PriorityTag text={item.priority} />}
                                <p className="text-xs leading-relaxed text-text-secondary flex-1">{item.body}</p>
                            </div>
                        ))}
                    </div>
                </Section>
            )}

            {/* Evidence Candidates */}
            {briefing.evidence_candidates?.length > 0 && (
                <Section
                    title={`Evidence Candidates (${briefing.evidence_candidates.length} clusters)`}
                    icon={<Shield className="h-3.5 w-3.5 text-white/30" />}
                    accentColor="rgba(255,255,255,0.08)"
                >
                    <div className="overflow-x-auto rounded-lg border border-border-subtle bg-[#080808]">
                        <table className="intel-table w-full text-left">
                            <thead>
                                <tr>
                                    <th>Threat Path</th>
                                    <th className="text-right">Domains</th>
                                    <th>Confidence</th>
                                    <th>Sample Domains</th>
                                </tr>
                            </thead>
                            <tbody>
                                {briefing.evidence_candidates.map(ec => (
                                    <tr key={ec.tp_id}>
                                        <td>
                                            <span className="font-mono text-sm text-text-primary">{ec.tp_id}</span>
                                        </td>
                                        <td className="text-right font-mono text-sm text-text-primary">{ec.domain_count}</td>
                                        <td>
                                            <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${ec.confidence === 'High'
                                                    ? 'bg-green-500/10 text-green-400 ring-1 ring-green-500/20'
                                                    : 'bg-yellow-500/10 text-yellow-400 ring-1 ring-yellow-500/20'
                                                }`}>{ec.confidence}</span>
                                        </td>
                                        <td>
                                            <div className="flex flex-wrap gap-1">
                                                {(ec.sample_domains || []).slice(0, 4).map(d => (
                                                    <button key={d} onClick={() => navigate(`/investigate/${d}`)}
                                                        className="font-mono text-xs text-text-secondary hover:text-text-primary hover:underline transition-colors"
                                                    >{d}</button>
                                                ))}
                                                {(ec.sample_domains?.length || 0) > 4 && (
                                                    <span className="text-[10px] text-text-muted">+{ec.sample_domains.length - 4}</span>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </Section>
            )}

            {/* Registrar Risk Outlook */}
            {briefing.registrar_risk_outlook && (
                <Section title="Registrar Risk Outlook" icon={<BarChart3 className="h-3.5 w-3.5 text-white/30" />} accentColor="rgba(255,255,255,0.08)" defaultOpen={false}>
                    <p className="text-xs leading-relaxed text-text-secondary">
                        {highlightConfidence(briefing.registrar_risk_outlook)}
                    </p>
                </Section>
            )}

            {/* Classification Footer */}
            <div className="briefing-classification">
                UNCLASSIFIED // END OF BRIEFING
            </div>
        </div>
    );
}
