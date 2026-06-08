import { cx } from "@/shared/lib/cx";

import ChartPanel from "./ChartPanel";
import type { ObservabilitySection as Section, SectionAccent } from "../lib/panels";
import type { EnvelopeMap } from "../types";

const accentBar: Record<SectionAccent, string> = {
  primary: "bg-primary",
  info: "bg-info",
  warning: "bg-warning",
  danger: "bg-danger",
  success: "bg-success",
};

function gridColumns(count: number): string {
  if (count <= 2) return "md:grid-cols-2";
  if (count === 4) return "md:grid-cols-2";
  return "md:grid-cols-2 xl:grid-cols-3";
}

export default function ObservabilitySection({
  section,
  envelopes,
  available,
}: {
  section: Section;
  envelopes: EnvelopeMap;
  available: boolean;
}) {
  return (
    <section className="space-y-3">
      <div className="flex items-start gap-2.5">
        <span className={cx("mt-0.5 h-8 w-[3px] shrink-0 rounded-full", accentBar[section.accent])} aria-hidden="true" />
        <div className="min-w-0">
          <h3 className="text-[13px] font-semibold tracking-tight text-foreground">{section.title}</h3>
          <p className="text-xs text-muted-foreground">{section.description}</p>
        </div>
      </div>
      <div className={cx("grid grid-cols-1 gap-3", gridColumns(section.panels.length))}>
        {section.panels.map((panel) => (
          <ChartPanel key={panel.id} panel={panel} envelopes={envelopes} available={available} />
        ))}
      </div>
    </section>
  );
}
