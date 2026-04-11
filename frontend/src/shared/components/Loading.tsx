export default function Loading({ label = "Loading..." }: { label?: string }) {
  return (
    <div className="ui-loading-state" role="status" aria-live="polite">
      <span
        className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-muted-foreground/35 border-t-primary"
        aria-hidden="true"
      />
      <span>{label}</span>
    </div>
  );
}
