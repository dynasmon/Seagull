export default function Loading({ label = "Loading..." }: { label?: string }) {
  return <div className="text-sm text-[var(--muted)]">{label}</div>;
}
