import Tooltip from './Tooltip';
import { tpRegistry } from '@/data/fpRegistry';

export default function FlameBadge({ tpId }) {
  if (!tpId) return null;

  const description = tpRegistry[tpId] || 'FLAME Threat Path — structured threat intelligence tracking ID';

  return (
    <Tooltip text={`${tpId}: ${description}`}>
      <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-xs font-medium text-orange-400/80 ring-1 ring-orange-500/15 bg-orange-500/8">
        🔥 {tpId}
      </span>
    </Tooltip>
  );
}
