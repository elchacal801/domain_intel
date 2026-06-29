import Tooltip from './Tooltip';
import { fpRegistry } from '@/data/fpRegistry';

export default function ConfidenceBadge({ score, fpId }) {
  if (score == null) return null;

  const num = Number(score);
  const bg =
    num > 75 ? 'bg-red-500/20 text-red-400 ring-red-500/20'
      : num >= 50 ? 'bg-yellow-500/15 text-yellow-400 ring-yellow-500/20'
        : 'bg-emerald-500/15 text-emerald-400 ring-emerald-500/20';

  const tip = fpId && fpRegistry[fpId]
    ? `${num}% confidence — ${fpRegistry[fpId].description}`
    : `${num}% match confidence score`;

  return (
    <Tooltip text={tip}>
      <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ring-1 ${bg}`}>
        {num}%
      </span>
    </Tooltip>
  );
}
