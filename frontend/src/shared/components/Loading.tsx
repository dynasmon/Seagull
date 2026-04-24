export default function Loading({ label = "Loading..." }: { label?: string }) {
  return (
    <div className="ui-loading-state" role="status" aria-live="polite">
      <span
        className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-border/70 border-t-primary"
        aria-hidden="true"
      />
      <span className="text-[12px]">{label}</span>
    </div>
  );
}
