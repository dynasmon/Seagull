export function sevVariant(sev: string): "critical" | "high" | "medium" | "low" | "neutral" {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "neutral";
}
