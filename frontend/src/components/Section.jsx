export default function Section({ title, children }) {
  return (
    <div className="rounded-lg border border-border-subtle bg-surface-raised">
      <div className="border-b border-border-subtle px-4 py-2">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400">
          {title}
        </h3>
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}
