export default function FlameBadge({ tpId }) {
  if (!tpId) return null;

  return (
    <span className="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 font-mono text-xs font-medium text-orange-300 ring-1 ring-orange-500/30"
      style={{ background: 'linear-gradient(135deg, rgba(154, 52, 18, 0.4), rgba(124, 45, 18, 0.25))' }}
    >
      <span className="text-orange-400">🔥</span>
      {tpId}
    </span>
  );
}
