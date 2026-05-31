import { useEffect, useMemo, useState } from "react";
import { EuiFieldNumber } from "@elastic/eui";

type Props = {
  value: number;
  onCommit: (next: number) => void;

  min?: number;
  max?: number;
  fallback?: number;

  disabled?: boolean;
  placeholder?: string;
  title?: string;

  className?: string;
};

function digitsOnly(v: string): string {
  return String(v ?? "").replace(/[^0-9]/g, "");
}

function clampInt(n: number, min?: number, max?: number) {
  let x = Math.trunc(n);
  if (typeof min === "number" && Number.isFinite(min)) x = Math.max(min, x);
  if (typeof max === "number" && Number.isFinite(max)) x = Math.min(max, x);
  return x;
}

export default function DraftNumberInput(props: Props) {
  const { value, onCommit, min, max, fallback, disabled, placeholder, title, className } = props;

  const safeValue = useMemo(() => {
    const base = Number.isFinite(value) ? value : (fallback ?? 0);
    return clampInt(base, min, max);
  }, [value, fallback, min, max]);

  const [focused, setFocused] = useState(false);
  const [draft, setDraft] = useState<string>(String(safeValue));

  useEffect(() => {
    if (focused) return;
    setDraft(String(safeValue));
  }, [focused, safeValue]);

  function commit(raw: string) {
    const parsed = Number.parseInt(String(raw ?? "").trim(), 10);
    const resolvedFallback = typeof fallback === "number" && Number.isFinite(fallback) ? fallback : safeValue;
    const next = Number.isFinite(parsed) ? parsed : resolvedFallback;
    const clamped = clampInt(next, min, max);
    setDraft(String(clamped));
    if (clamped !== safeValue) onCommit(clamped);
  }

  return (
    <EuiFieldNumber
      compressed
      fullWidth
      controlOnly
      inputMode="numeric"
      pattern="[0-9]*"
      min={min}
      max={max}
      step={1}
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
      className={className}
    />
  );
}
