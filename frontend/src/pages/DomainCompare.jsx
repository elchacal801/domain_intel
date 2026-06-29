import { useParams, useNavigate, Link } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { useData } from '@/context/DataContext';
import Section from '@/components/Section';
import {
    ArrowLeft, Search, ArrowLeftRight, Shield, Globe, Fingerprint,
    Server, AlertTriangle, Network, Brain,
} from 'lucide-react';

/* Field row with diff highlighting */
function CompareRow({ label, a, b }) {
    const valA = a == null || a === '' || a === 'N/A' ? '-' : String(a);
    const valB = b == null || b === '' || b === 'N/A' ? '-' : String(b);
    const differs = valA !== valB && valA !== '-' && valB !== '-';
    return (
        <tr className={differs ? 'compare-diff' : ''}>
            <td className="text-[10px] font-semibold uppercase tracking-widest py-1.5 px-3 w-[30%]"
                style={{ color: 'var(--text-muted)' }}>{label}</td>
            <td className={`text-xs font-mono py-1.5 px-3 w-[35%] ${differs ? 'compare-cell-a' : ''}`}
                style={{ color: 'var(--text-secondary)' }}>{valA}</td>
            <td className={`text-xs font-mono py-1.5 px-3 w-[35%] ${differs ? 'compare-cell-b' : ''}`}
                style={{ color: 'var(--text-secondary)' }}>{valB}</td>
        </tr>
    );
}

function RiskBadge({ score, level }) {
    if (score == null) return <span style={{ color: 'var(--text-muted)' }}>-</span>;
    const colors = {
        Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22c55e',
    };
    const c = colors[level] || '#888';
    return (
        <span className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-bold"
            style={{ background: `${c}15`, color: c, border: `1px solid ${c}33` }}>
            {score} - {level}
        </span>
    );
}

export default function DomainCompare() {
    const { domainA, domainB } = useParams();
    const navigate = useNavigate();
    const { loadDomain } = useData();
    const [dataA, setDataA] = useState(null);
    const [dataB, setDataB] = useState(null);
    const [loading, setLoading] = useState(true);
    const [searchA, setSearchA] = useState('');
    const [searchB, setSearchB] = useState('');

    useEffect(() => {
        let cancelled = false;
        async function load() {
            setLoading(true);
            const [a, b] = await Promise.all([loadDomain(domainA), loadDomain(domainB)]);
            if (!cancelled) { setDataA(a); setDataB(b); setLoading(false); }
        }
        load();
        return () => { cancelled = true; };
    }, [domainA, domainB, loadDomain]);

    function handleSwap() {
        navigate(`/compare/${domainB}/${domainA}`, { replace: true });
    }

    function handleNewCompare(e) {
        e.preventDefault();
        const a = searchA.trim() || domainA;
        const b = searchB.trim() || domainB;
        if (a && b) navigate(`/compare/${a}/${b}`);
    }

    if (loading) {
        return (
            <div className="flex h-80 items-center justify-center">
                <div className="flex flex-col items-center gap-3">
                    <div className="h-7 w-7 animate-spin rounded-full border-2" style={{ borderColor: 'var(--border-subtle)', borderTopColor: 'var(--text-muted)' }} />
                    <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Loading comparison...</span>
                </div>
            </div>
        );
    }

    // Build sections of fields
    const sections = [
        {
            title: 'DNS & Network', icon: <Globe className="h-3.5 w-3.5" style={{ color: 'var(--text-muted)' }} />,
            fields: [
                ['IP Address', 'ip'], ['ASN', 'asn'], ['ASN Org', 'asn_org'],
                ['HTTP Status', 'http_status'], ['HTTPS Status', 'https_status'],
                ['MX Records', 'mx_records'], ['NS Records', 'ns_records'],
                ['Primary MX', 'primary_mx'], ['Server', 'server'],
            ],
        },
        {
            title: 'WHOIS / Registration', icon: <Shield className="h-3.5 w-3.5" style={{ color: 'var(--text-muted)' }} />,
            fields: [
                ['Registrar', 'registrar'], ['Registrant Org', 'registrant_org'],
                ['Creation Date', 'creation_date'], ['Expiration Date', 'whois_expiration_date'],
                ['Age (days)', 'age_days'], ['TLD', 'tld'],
            ],
        },
        {
            title: 'Risk & Intelligence', icon: <AlertTriangle className="h-3.5 w-3.5" style={{ color: 'var(--text-muted)' }} />,
            fields: [
                ['AI Category', 'ai_category'], ['AI Confidence', 'ai_confidence'],
                ['Typosquat Target', 'typosquat_target'], ['Similarity Score', 'similarity_score'],
                ['VT Malicious', 'vt_malicious_count'], ['VT Last Analysis', 'vt_last_analysis'],
                ['PhishTank Match', 'phishtank_match'], ['RBL Hits', 'rbl_hits'],
                ['OpenSanctions Score', 'os_match_score'],
            ],
        },
        {
            title: 'Infrastructure', icon: <Server className="h-3.5 w-3.5" style={{ color: 'var(--text-muted)' }} />,
            fields: [
                ['Shodan Ports', 'shodan_ports'], ['Shodan OS', 'shodan_os'],
                ['Shodan Vulns', 'shodan_vulns'], ['Shodan Tags', 'shodan_tags'],
                ['OpenClaw Agent Type', 'openclaw_agent_type'],
                ['OpenClaw Exposure', 'openclaw_exposure_level'],
            ],
        },
    ];

    return (
        <div className="mx-auto max-w-6xl space-y-5 animate-fade-in">
            {/* Header */}
            <div className="flex items-center gap-3 mb-4">
                <Link to="/investigate" className="rounded-md p-1.5 transition-colors hover:bg-white/5"
                    style={{ color: 'var(--text-muted)' }}>
                    <ArrowLeft className="h-4 w-4" />
                </Link>
                <ArrowLeftRight className="h-4 w-4" style={{ color: 'var(--text-muted)' }} />
                <h1 className="text-lg font-normal" style={{ color: 'var(--text-primary)' }}>Domain Comparison</h1>
            </div>

            {/* Domain Selector */}
            <form onSubmit={handleNewCompare} className="glass-card p-4">
                <div className="grid grid-cols-[1fr_auto_1fr_auto] gap-3 items-center">
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-muted)' }} />
                        <input
                            value={searchA} onChange={e => setSearchA(e.target.value)}
                            placeholder={domainA}
                            className="w-full rounded-md border py-2 pl-9 pr-3 text-xs font-mono outline-none"
                            style={{ background: 'var(--bg-surface-input)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }}
                        />
                    </div>
                    <button type="button" onClick={handleSwap} className="theme-toggle" title="Swap domains">
                        <ArrowLeftRight className="h-3.5 w-3.5" />
                    </button>
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-muted)' }} />
                        <input
                            value={searchB} onChange={e => setSearchB(e.target.value)}
                            placeholder={domainB}
                            className="w-full rounded-md border py-2 pl-9 pr-3 text-xs font-mono outline-none"
                            style={{ background: 'var(--bg-surface-input)', borderColor: 'var(--border-subtle)', color: 'var(--text-primary)' }}
                        />
                    </div>
                    <button type="submit" className="rounded-md px-3 py-2 text-xs font-medium transition-colors"
                        style={{ background: 'var(--nav-active-bg)', color: 'var(--text-primary)', border: '1px solid var(--border-subtle)' }}>
                        Compare
                    </button>
                </div>
            </form>

            {/* Risk Score Overview */}
            <div className="glass-card p-4">
                <div className="grid grid-cols-[30%_35%_35%] gap-3 items-center">
                    <span className="text-[10px] font-bold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
                        Risk Score
                    </span>
                    <div className="text-center">
                        <div className="text-xs font-mono mb-1" style={{ color: 'var(--text-secondary)' }}>{domainA}</div>
                        <RiskBadge score={dataA?.risk_score} level={dataA?.risk_level} />
                    </div>
                    <div className="text-center">
                        <div className="text-xs font-mono mb-1" style={{ color: 'var(--text-secondary)' }}>{domainB}</div>
                        <RiskBadge score={dataB?.risk_score} level={dataB?.risk_level} />
                    </div>
                </div>
            </div>

            {/* Fingerprint Matches */}
            {(dataA?.matches?.length > 0 || dataB?.matches?.length > 0) && (
                <Section title="Fingerprint Matches" icon={<Fingerprint className="h-3.5 w-3.5" style={{ color: 'var(--text-muted)' }} />}>
                    <div className="grid grid-cols-2 gap-4 p-3">
                        <div>
                            <div className="text-[10px] font-semibold uppercase tracking-widest mb-2" style={{ color: 'var(--text-muted)' }}>{domainA}</div>
                            {(dataA?.matches || []).map((m, i) => (
                                <div key={i} className="text-xs font-mono mb-1" style={{ color: 'var(--text-secondary)' }}>
                                    {m.fp_id} - {m.fp_name} ({m.confidence}%)
                                </div>
                            ))}
                            {!dataA?.matches?.length && <span className="text-xs" style={{ color: 'var(--text-muted)' }}>None</span>}
                        </div>
                        <div>
                            <div className="text-[10px] font-semibold uppercase tracking-widest mb-2" style={{ color: 'var(--text-muted)' }}>{domainB}</div>
                            {(dataB?.matches || []).map((m, i) => (
                                <div key={i} className="text-xs font-mono mb-1" style={{ color: 'var(--text-secondary)' }}>
                                    {m.fp_id} - {m.fp_name} ({m.confidence}%)
                                </div>
                            ))}
                            {!dataB?.matches?.length && <span className="text-xs" style={{ color: 'var(--text-muted)' }}>None</span>}
                        </div>
                    </div>
                </Section>
            )}

            {/* Comparison Sections */}
            {sections.map(section => (
                <Section key={section.title} title={section.title} icon={section.icon} defaultOpen>
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr>
                                    <th className="text-left text-[10px] font-semibold uppercase tracking-widest py-1.5 px-3"
                                        style={{ color: 'var(--text-muted)' }}>Field</th>
                                    <th className="text-left text-[10px] font-semibold uppercase tracking-widest py-1.5 px-3"
                                        style={{ color: 'var(--text-muted)' }}>{domainA}</th>
                                    <th className="text-left text-[10px] font-semibold uppercase tracking-widest py-1.5 px-3"
                                        style={{ color: 'var(--text-muted)' }}>{domainB}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {section.fields.map(([label, key]) => (
                                    <CompareRow key={key} label={label} a={dataA?.[key]} b={dataB?.[key]} />
                                ))}
                            </tbody>
                        </table>
                    </div>
                </Section>
            ))}

            {/* No Data States */}
            {(!dataA && !dataB) && (
                <div className="glass-card p-8 text-center">
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No data found for either domain.</p>
                </div>
            )}
        </div>
    );
}
