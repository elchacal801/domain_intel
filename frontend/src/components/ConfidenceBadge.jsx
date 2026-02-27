import { cn } from '@/lib/utils';

export default function ConfidenceBadge({ score }) {
  if (score == null) return null;

  const num = Number(score);
  const color =
    num > 75
      ? 'bg-red-600'
      : num >= 50
        ? 'bg-yellow-600'
        : 'bg-green-600';

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold text-white',
        color,
      )}
    >
      {num}%
    </span>
  );
}
