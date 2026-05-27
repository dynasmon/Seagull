import type { HygieneDomain } from "../types";

export function warningMatchesDomain(text: string, domain: HygieneDomain): boolean {
  const value = (text || "").toLowerCase();
  if (!value) return false;
  if (domain === "dashboard") return true;
  if (domain === "system") return /(kernel|os|hostname|platform|filesystem|uptime|hardware)/i.test(value);
  if (domain === "software") return /(package|version|manager|dependency|inventory|hash)/i.test(value);
  if (domain === "processes") return /(process|pid|runtime|command|exec|thread)/i.test(value);
  if (domain === "network") return /(network|interface|port|socket|route|dns|ip|tcp|udp)/i.test(value);
  if (domain === "identity") return /(identity|user|group|host|domain|role|tag|metadata|auth)/i.test(value);
  return /(service|daemon|listener|unit|systemd|http|ssh|agent)/i.test(value);
}
