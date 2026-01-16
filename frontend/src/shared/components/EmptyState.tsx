export default function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="rounded-md border border-[var(--border)] bg-[var(--panel)] p-4">
      <div className="text-sm font-semibold">{title}</div>
      {hint && <div className="mt-1 text-sm text-[var(--muted)]">{hint}</div>}
    </div>
  );
}
