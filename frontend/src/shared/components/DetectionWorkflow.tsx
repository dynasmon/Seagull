import { NavLink } from "react-router-dom";

import { cx } from "@/shared/lib/cx";

const FLOW_STEPS = [
  { label: "Alerts Queue", to: "/alerts/queue" },
  { label: "Alert Rules", to: "/alerts/rules" },
  { label: "Attack Chains", to: "/attack-chain" },
  { label: "Correlation Findings", to: "/correlations/findings" },
  { label: "Correlation Rules", to: "/correlations/rules" },
  { label: "Investigations", to: "/investigations" },
];

export function DetectionWorkflowRail({
  className,
  compact = false,
}: {
  className?: string;
  compact?: boolean;
}) {
  return (
    <div className={cx("ui-toolbar-shell flex flex-wrap items-center gap-1.5", className)}>
      <span className="mr-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">
        Workflow
      </span>
      {FLOW_STEPS.map((step) => (
        <NavLink
          key={step.to}
          to={step.to}
          className={({ isActive }) =>
            cx(
              "inline-flex items-center rounded-md border px-2 py-1 text-[11px] font-mono uppercase tracking-wider transition-colors",
              isActive
                ? "border-primary/45 bg-primary/10 text-foreground"
                : "border-border/60 bg-background/30 text-muted-foreground hover:bg-muted/30 hover:text-foreground",
              compact && "px-1.5 py-0.5 text-[10px]",
            )
          }
        >
          {step.label}
        </NavLink>
      ))}
    </div>
  );
}

export default DetectionWorkflowRail;
