import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';

export default function Section({ title, icon, accentColor, children, defaultOpen = true }) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div className="section-card">
      <button
        onClick={() => setIsOpen(v => !v)}
        className="section-card-header w-full cursor-pointer select-none"
      >
        {accentColor && (
          <div className="h-4 w-1 rounded-full" style={{ background: accentColor }} />
        )}
        {icon}
        <h3 className="flex-1 text-left text-xs font-semibold uppercase tracking-wider text-text-muted">
          {title}
        </h3>
        {isOpen ? (
          <ChevronUp className="h-3.5 w-3.5 text-text-muted" />
        ) : (
          <ChevronDown className="h-3.5 w-3.5 text-text-muted" />
        )}
      </button>
      {isOpen && (
        <div className="p-4 animate-fade-in">{children}</div>
      )}
    </div>
  );
}
