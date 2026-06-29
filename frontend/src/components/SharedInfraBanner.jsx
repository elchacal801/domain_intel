import { AlertTriangle } from 'lucide-react';

export default function SharedInfraBanner({ provider, providerLabel, providerCategory }) {
  if (!providerLabel) return null;

  const subtitle =
    providerCategory === 'email'
      ? 'Co-location on this mail server does not indicate operational relationship.'
      : providerCategory === 'dns'
        ? 'Shared DNS provider does not indicate operational relationship.'
        : providerCategory === 'web_hosting'
          ? 'Shared web hosting/CDN provider does not indicate operational relationship.'
          : 'Co-location on this infrastructure does not indicate operational relationship.';

  return (
    <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-2">
      <div className="flex items-center gap-1.5">
        <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0" />
        <span className="text-xs text-amber-400">
          <span className="font-medium">Shared Infrastructure</span>
          {' \u2014 '}
          {providerLabel}
        </span>
      </div>
      <p className="text-[10px] text-text-muted mt-0.5 ml-5">
        {subtitle}
      </p>
    </div>
  );
}
