export default function FlameBadge({ tpId }) {
  if (!tpId) return null;

  return (
    <span className="inline-flex items-center rounded-full bg-orange-900/60 px-2.5 py-0.5 font-mono text-xs font-medium text-orange-300 ring-1 ring-orange-700/50">
      {tpId}
    </span>
  );
}
