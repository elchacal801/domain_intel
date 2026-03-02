export default function ResolutionChain({ chain, className = '' }) {
  if (!chain || !chain.path || chain.path.length === 0) return null;

  const { path, mx_shared, mx_provider_label } = chain;

  // Classify each element in the path for styling
  function getElementStyle(element, index) {
    const isRecordType = /^(MX|A|AAAA|CNAME|NS|TXT|SOA|SRV|PTR)$/i.test(element);
    const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(element);

    if (isRecordType) {
      return 'text-text-muted text-[10px] uppercase';
    }

    // Check if previous element was "MX" (case-insensitive)
    const prevElement = index > 0 ? path[index - 1] : null;
    if (prevElement && /^MX$/i.test(prevElement)) {
      return 'font-mono text-[#5b8abf]';
    }

    if (isIP) {
      return 'font-mono text-[#c98a5a]';
    }

    // Default: domain names and hostnames
    return 'font-mono text-text-primary';
  }

  return (
    <div className={`flex flex-wrap items-center gap-y-1 text-xs ${className}`}>
      {path.map((element, i) => (
        <span key={i} className="inline-flex items-center">
          {i > 0 && <span className="text-text-muted mx-1">{'\u2192'}</span>}
          <span className={getElementStyle(element, i)}>{element}</span>
        </span>
      ))}
      {mx_shared && mx_provider_label && (
        <span className="ml-2 rounded bg-amber-500/10 border border-amber-500/20 px-1.5 py-0.5 text-[9px] text-amber-400">
          {mx_provider_label}
        </span>
      )}
    </div>
  );
}
