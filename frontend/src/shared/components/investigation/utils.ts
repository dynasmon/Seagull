export function copyTextToClipboard(text: string): Promise<boolean> {
  if (!text) return Promise.resolve(false);
  if (navigator.clipboard?.writeText) {
    return navigator.clipboard
      .writeText(text)
      .then(() => true)
      .catch(() => false);
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return Promise.resolve(ok);
  } catch {
    return Promise.resolve(false);
  }
}

export function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function padTimestampUnit(value: number): string {
  return String(value).padStart(2, "0");
}

export function formatInvestigationTimestamp(value: string | number | Date | null | undefined): string {
  if (value === null || value === undefined || value === "") return "-";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);

  const yyyy = date.getFullYear();
  const mm = padTimestampUnit(date.getMonth() + 1);
  const dd = padTimestampUnit(date.getDate());
  const hh = padTimestampUnit(date.getHours());
  const mi = padTimestampUnit(date.getMinutes());
  const ss = padTimestampUnit(date.getSeconds());
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}
