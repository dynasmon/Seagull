import { Button } from "@/shared/components/Button";

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
      <Button variant="secondary" size="md" onClick={onRefresh} disabled={busy}>
        {busy ? "Refreshing..." : "Refresh now"}
      </Button>
    </div>
  );
}

