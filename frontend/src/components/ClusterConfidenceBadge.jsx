export default function ClusterConfidenceBadge({ confidence, confidenceLevel }) {
  if (confidence == null) return null;

  const num = Number(confidence);
  const level = confidenceLevel || (num >= 70 ? 'high' : num >= 40 ? 'medium' : 'low');

  const color =
    level === 'high' ? '#ef4444'
      : level === 'medium' ? '#eab308'
        : '#6b7280';

  const label =
    level === 'high' ? 'High'
      : level === 'medium' ? 'Medium'
        : 'Low';

  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-semibold"
      style={{
        background: `${color}15`,
        color: color,
        boxShadow: `inset 0 0 0 1px ${color}30`,
      }}
    >
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ background: color }}
      />
      {label} ({num})
    </span>
  );
}
