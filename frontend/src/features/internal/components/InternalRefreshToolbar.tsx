export default function InternalRefreshToolbar({
  lastUpdatedLabel,
  onRefresh,
  busy = false,
}: {
  lastUpdatedLabel: string;
  onRefresh: () => void;
  busy?: boolean;
}) {
  return (
    <div className="ui-toolbar-shell flex flex-wrap items-center justify-between gap-3">
      <div className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">
        Last update: {lastUpdatedLabel}
      </div>
      <button
        type="button"
        onClick={onRefresh}
        disabled={busy}
        className="ui-btn-secondary h-9 px-3 text-xs font-mono uppercase tracking-widest disabled:opacity-60"
      >
        {busy ? "Refreshing..." : "Refresh now"}
      </button>
    </div>
  );
}

