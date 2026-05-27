export function fmtDateTime(iso?: string | null) {
  if (!iso) return "-";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const d = new Date(t);
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

export function fmtMinutes(min?: number | null) {
  if (min === null || min === undefined || !Number.isFinite(min)) return "-";
  if (min < 1) return "< 1m";
  if (min < 60) return `${Math.round(min)}m`;
  const h = Math.floor(min / 60);
  const m = Math.round(min % 60);
  if (h < 24) return `${h}h ${String(m).padStart(2, "0")}m`;
  const d = Math.floor(h / 24);
  const hh = h % 24;
  return `${d}d ${hh}h`;
}
