import { useEffect, useMemo, useState } from "react";

import { cx } from "@/shared/lib/cx";

type Props = {
  value: number;
  onCommit: (next: number) => void;

  min?: number;
  max?: number;
  fallback?: number;

  disabled?: boolean;
  placeholder?: string;
  title?: string;

  /**
   * Tailwind classes for the <input/>.
   */
  className?: string;
};

function digitsOnly(v: string): string {
  return String(v ?? "").replace(/[^0-9]/g, "");
}

function clampInt(n: number, min?: number, max?: number) {
  let x = Math.trunc(n);
  if (Number.isFinite(min as any)) x = Math.max(min as number, x);
  if (Number.isFinite(max as any)) x = Math.min(max as number, x);
  return x;
}

/**
 * Numeric input that does NOT "jump" while typing.
 *
 * Controlled <input type="number"/> + Number()/clamp on each keypress will snap values
 * when users delete, paste, or type partial numbers. This component keeps a draft string
 * while focused and only commits on blur/Enter.
 */
export default function DraftNumberInput(props: Props) {
  const { value, onCommit, disabled, placeholder, title, className } = props;

  const safeValue = useMemo(() => {
    const base = Number.isFinite(value) ? value : (props.fallback ?? 0);
    return clampInt(base, props.min, props.max);
  }, [value, props.fallback, props.min, props.max]);

  const [focused, setFocused] = useState(false);
  const [draft, setDraft] = useState<string>(String(safeValue));

  useEffect(() => {
    if (focused) return;
    setDraft(String(safeValue));
  }, [focused, safeValue]);

  function commit(raw: string) {
    const parsed = Number.parseInt(String(raw ?? "").trim(), 10);
    const fallback = Number.isFinite(props.fallback as any) ? (props.fallback as number) : safeValue;
    const next = Number.isFinite(parsed) ? parsed : fallback;
    const clamped = clampInt(next, props.min, props.max);
    setDraft(String(clamped));
    if (clamped !== safeValue) onCommit(clamped);
  }

  return (
    <input
      type="text"
      inputMode="numeric"
      pattern="[0-9]*"
      value={draft}
      placeholder={placeholder}
      title={title}
      disabled={disabled}
      onFocus={() => setFocused(true)}
      onBlur={() => {
        setFocused(false);
        commit(draft);
      }}
      onChange={(e) => setDraft(digitsOnly(e.target.value))}
      onKeyDown={(e) => {
        if (e.key === "Enter") {
          e.currentTarget.blur();
        }
        if (e.key === "Escape") {
          setDraft(String(safeValue));
          e.currentTarget.blur();
        }
      }}
      className={cx(className)}
    />
  );
}
