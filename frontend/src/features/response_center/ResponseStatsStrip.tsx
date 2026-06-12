import { EuiPanel, EuiStat } from "@elastic/eui";

import { cx } from "@/shared/lib/cx";

export interface ResponseStats {
  total: number;
  queued: number;
  running: number;
  succeeded: number;
  failed: number;
  inactive: number;
}

interface ResponseStatsStripProps {
  stats: ResponseStats;
  activeStatuses: string[];
  onSelect: (statuses: string[]) => void;
}

type StatColor = "default" | "primary" | "warning" | "success" | "danger" | "subdued";

const CARDS: Array<{ key: keyof ResponseStats; label: string; statuses: string[]; color: StatColor }> = [
  { key: "total", label: "Total", statuses: [], color: "default" },
  { key: "queued", label: "Queued", statuses: ["pending", "delivered"], color: "primary" },
  { key: "running", label: "Running", statuses: ["running"], color: "warning" },
  { key: "succeeded", label: "Succeeded", statuses: ["success"], color: "success" },
  { key: "failed", label: "Failed", statuses: ["failed"], color: "danger" },
  { key: "inactive", label: "Cancelled / Expired", statuses: ["cancelled", "expired"], color: "subdued" },
];

function sameSet(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const setB = new Set(b);
  return a.every((value) => setB.has(value));
}

export default function ResponseStatsStrip({ stats, activeStatuses, onSelect }: ResponseStatsStripProps) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
      {CARDS.map((card) => {
        const active = card.statuses.length === 0 ? activeStatuses.length === 0 : sameSet(activeStatuses, card.statuses);
        return (
          <EuiPanel
            key={card.key}
            hasBorder
            hasShadow={false}
            paddingSize="m"
            borderRadius="m"
            color={active ? "primary" : "plain"}
            onClick={() => onSelect(active && card.statuses.length ? [] : card.statuses)}
            className={cx("min-w-0 cursor-pointer transition-colors", !active && "hover:border-primary/40")}
            aria-pressed={active}
          >
            <EuiStat
              title={stats[card.key]}
              description={card.label}
              titleColor={card.color}
              titleSize="m"
              reverse
            />
          </EuiPanel>
        );
      })}
    </div>
  );
}
