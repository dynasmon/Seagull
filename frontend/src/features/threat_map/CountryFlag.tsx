import { useState } from "react";

import { cx } from "@/shared/lib/cx";

import { countryFlagCode } from "./countryDisplay";

export function CountryFlag({ country }: { country: string | null | undefined }) {
  const code = countryFlagCode(country);
  const [missing, setMissing] = useState(false);

  if (!code || missing) return null;

  return (
    <img
      src={`/flags/3x2/${code}.svg`}
      alt=""
      aria-hidden
      loading="lazy"
      decoding="async"
      onError={() => setMissing(true)}
      className="inline-block h-[11px] w-4 shrink-0 rounded-[2px] object-cover align-[-1px] ring-1 ring-black/25"
    />
  );
}

export function CountryLabel({
  country,
  text,
  className,
}: {
  country: string | null | undefined;
  text?: string | null;
  className?: string;
}) {
  const label = (text ?? country ?? "").trim();

  return (
    <span className={cx("inline-flex min-w-0 items-center gap-1.5", className)}>
      <CountryFlag country={country} />
      {label ? <span className="min-w-0 truncate">{label}</span> : null}
    </span>
  );
}
