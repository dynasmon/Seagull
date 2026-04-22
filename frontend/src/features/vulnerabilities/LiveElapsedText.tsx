import { useEffect, useState } from "react";

import { fmtSec } from "./scanUtils";

/**
 * Renders a live-updating elapsed/duration string in its own component so the timer
 * does not trigger re-renders in parent components.
 * When endIso is absent, ticks every second. When endIso is set, renders statically.
 */
export function LiveElapsedText({
  startIso,
  endIso,
  className,
}: {
  startIso?: string | null;
  endIso?: string | null;
  className?: string;
}) {
  const active = Boolean(startIso && !endIso);
  const [, setTick] = useState(0);

  useEffect(() => {
    if (!active) return;
    let timerId: number | null = null;

    const scheduleNextTick = () => {
      const now = Date.now();
      const remainderMs = now % 1000;
      const delayMs = remainderMs === 0 ? 1000 : 1000 - remainderMs;
      timerId = window.setTimeout(() => {
        setTick((n) => n + 1);
        scheduleNextTick();
      }, delayMs);
    };

    scheduleNextTick();
    return () => {
      if (timerId !== null) window.clearTimeout(timerId);
    };
  }, [active]);

  const start = Date.parse(startIso ?? "");
  if (Number.isNaN(start)) return <span className={className}>-</span>;
  const end = endIso ? Date.parse(endIso) : Date.now();
  return (
    <span className={className}>
      {fmtSec(Math.max(0, Math.floor((end - start) / 1000)))}
    </span>
  );
}
