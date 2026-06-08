import { EuiStat } from "@elastic/eui";

import type { MetricTone } from "@/shared/components/MetricCard";
import { Panel } from "@/shared/components/Panel";

import { formatByUnit } from "../lib/format";
import { STAT_BAND } from "../lib/panels";
import { latestValue } from "../lib/transform";
import type { EnvelopeMap } from "../types";

const toneColor: Record<MetricTone, string> = {
  default: "default",
  success: "success",
  warning: "warning",
  danger: "danger",
  info: "primary",
};

export default function StatBand({ envelopes }: { envelopes: EnvelopeMap }) {
  return (
    <Panel title="Platform health" subtitle="Latest rates and pipeline state in the selected window">
      <div className="grid grid-cols-2 gap-x-4 gap-y-5 sm:grid-cols-3 lg:grid-cols-5">
        {STAT_BAND.map((stat) => {
          const value = latestValue(envelopes[stat.key]);
          const tone = stat.tone ? stat.tone(value) : "default";
          return (
            <EuiStat
              key={stat.key}
              title={formatByUnit(stat.unit, value)}
              description={stat.label}
              titleColor={toneColor[tone]}
              titleSize="s"
            />
          );
        })}
      </div>
    </Panel>
  );
}
