import { cn } from '@/lib/utils';

export default function ConfidenceBadge({ score }) {
  if (score == null) return null;

  const num = Number(score);
  const style =
    num > 75
      ? 'bg-gradient-to-r from-red-600 to-red-500 shadow-red-500/20'
      : num >= 50
        ? 'bg-gradient-to-r from-amber-600 to-yellow-500 shadow-yellow-500/20'
        : 'bg-gradient-to-r from-emerald-600 to-green-500 shadow-green-500/20';

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold text-white shadow-sm',
        style,
      )}
    >
      {num}%
    </span>
  );
}
