import type { PackageEntry } from "../types";

export function filterPackages(packages: PackageEntry[], q: string): PackageEntry[] {
  const s = (q || "").trim().toLowerCase();
  if (!s) return packages;
  return packages.filter((p) => {
    const name = (p.name || "").toLowerCase();
    const ver = (p.version || "").toLowerCase();
    const arch = (p.arch || "").toLowerCase();
    return name.includes(s) || ver.includes(s) || arch.includes(s);
  });
}
