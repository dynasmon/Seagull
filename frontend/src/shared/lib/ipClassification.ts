export type IpDisplayLabel =
  | "Public"
  | "Internal"
  | "Private"
  | "Loopback"
  | "Link-local"
  | "CGNAT"
  | "Reserved/Test"
  | "Invalid"
  | "Unknown";

export type IpAddressContext = {
  ip?: string | null;
  version?: number | null;
  scope?: string | null;
  label?: string | null;
  is_internal?: boolean | null;
  is_public?: boolean | null;
  is_special?: boolean | null;
  matched_cidr?: string | null;
  matchedCidr?: string | null;
  match_source?: string | null;
  matchSource?: string | null;
};

export type IpFlowContext = {
  src?: IpAddressContext | null;
  dst?: IpAddressContext | null;
  flow?: Record<string, unknown> | null;
};

export type IpContextInput = IpAddressContext | IpFlowContext | null | undefined;
export type IpContextSide = "src" | "dst";

export type IpDisplayClassification = {
  ip: string;
  label: IpDisplayLabel;
  scope: string;
  matchedCidr: string | null;
  matchSource: string | null;
  source: "backend" | "fallback";
  isInternal: boolean;
  isPublic: boolean;
  isValid: boolean;
};

const REQUIRED_LABELS = new Set<IpDisplayLabel>([
  "Public",
  "Internal",
  "Private",
  "Loopback",
  "Link-local",
  "CGNAT",
  "Reserved/Test",
  "Invalid",
  "Unknown",
]);

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : null;
}

function clean(value: unknown): string {
  return String(value ?? "").trim();
}

function normalizeKey(value: unknown): string {
  return clean(value).toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

function requiredLabel(value: unknown): IpDisplayLabel | null {
  const raw = clean(value);
  if (!raw) return null;
  if (REQUIRED_LABELS.has(raw as IpDisplayLabel)) return raw as IpDisplayLabel;

  switch (normalizeKey(raw)) {
    case "public":
    case "public_internet":
      return "Public";
    case "internal":
    case "internal_network":
      return "Internal";
    case "private":
    case "private_address":
    case "unique_local":
    case "unique_local_address":
      return "Private";
    case "loopback":
      return "Loopback";
    case "link_local":
    case "linklocal":
      return "Link-local";
    case "cgnat":
    case "carrier_grade_nat":
      return "CGNAT";
    case "reserved":
    case "reserved_test":
    case "test":
    case "documentation":
    case "benchmark":
    case "multicast":
    case "unspecified":
    case "special":
      return "Reserved/Test";
    case "invalid":
      return "Invalid";
    case "unknown":
      return "Unknown";
    default:
      return null;
  }
}

export function labelForIpScope(scope?: string | null, fallbackLabel?: string | null): IpDisplayLabel {
  const byScope = requiredLabel(scope);
  if (byScope) return byScope;
  return requiredLabel(fallbackLabel) ?? "Unknown";
}

function contextHasClassification(ctx: Record<string, unknown>): boolean {
  return (
    ctx.scope !== undefined ||
    ctx.label !== undefined ||
    ctx.is_internal !== undefined ||
    ctx.is_public !== undefined ||
    ctx.matched_cidr !== undefined ||
    ctx.match_source !== undefined ||
    ctx.matchedCidr !== undefined ||
    ctx.matchSource !== undefined
  );
}

export function getFlowIpContext(ipContext: IpContextInput, side: IpContextSide): IpAddressContext | null {
  const record = asRecord(ipContext);
  if (!record) return null;

  const direct = asRecord(record[side]);
  if (direct) return direct as IpAddressContext;
  if (contextHasClassification(record)) return record as IpAddressContext;
  return null;
}

function inferFlowIpContext(ipContext: IpContextInput, ip: string): IpAddressContext | null {
  const record = asRecord(ipContext);
  if (!record) return null;
  if (contextHasClassification(record)) return record as IpAddressContext;

  const src = asRecord(record.src) as IpAddressContext | null;
  const dst = asRecord(record.dst) as IpAddressContext | null;
  const raw = clean(ip);
  if (src && clean(src.ip) === raw) return src;
  if (dst && clean(dst.ip) === raw) return dst;
  return null;
}

export function ipContextFromFlatFields(record: unknown, side: IpContextSide = "src"): IpAddressContext | null {
  const row = asRecord(record);
  if (!row) return null;

  const ip = clean(row[`${side}_ip`]);
  const scope = clean(row[`${side}_ip_scope`]);
  const label = clean(row[`${side}_ip_label`]);
  const isInternal = row[`${side}_is_internal`];
  const isPublic = row[`${side}_is_public`];

  if (!ip && !scope && !label && typeof isInternal !== "boolean" && typeof isPublic !== "boolean") return null;

  return {
    ip: ip || null,
    scope: scope || null,
    label: label || null,
    is_internal: typeof isInternal === "boolean" ? isInternal : null,
    is_public: typeof isPublic === "boolean" ? isPublic : null,
  };
}

function fromBackendContext(ip: string, ctx: IpAddressContext | null): IpDisplayClassification | null {
  const record = asRecord(ctx);
  if (!record || !contextHasClassification(record)) return null;

  const rawIp = clean(ip) || clean(record.ip);
  const rawScope = clean(record.scope) || "unknown";
  const scope = rawIp ? rawScope : "unknown";
  let label = labelForIpScope(scope, clean(record.label) || null);

  if (!rawIp) label = "Unknown";
  if (label === "Unknown") {
    if (record.is_public === true) label = "Public";
    else if (record.is_internal === true) label = "Internal";
  }

  return {
    ip: rawIp,
    label,
    scope,
    matchedCidr: clean(record.matched_cidr ?? record.matchedCidr) || null,
    matchSource: clean(record.match_source ?? record.matchSource) || null,
    source: "backend",
    isInternal: record.is_internal === true || label === "Internal" || label === "Private" || label === "Loopback" || label === "Link-local" || label === "CGNAT",
    isPublic: record.is_public === true || label === "Public",
    isValid: label !== "Invalid" && Boolean(rawIp),
  };
}

function ipv4Parts(ip: string): number[] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((part) => {
    if (!/^\d{1,3}$/.test(part)) return Number.NaN;
    const n = Number(part);
    return n >= 0 && n <= 255 ? n : Number.NaN;
  });
  return nums.every(Number.isFinite) ? nums : null;
}

function parseIpv6Groups(rawIp: string): number[] | null {
  const ip = rawIp.split("%")[0];
  if (!ip || /[^0-9a-fA-F:.]/.test(ip)) return null;
  const doubleColonCount = (ip.match(/::/g) || []).length;
  if (doubleColonCount > 1) return null;

  function parseSide(side: string): number[] | null {
    if (!side) return [];
    const pieces = side.split(":");
    const groups: number[] = [];
    for (let i = 0; i < pieces.length; i += 1) {
      const piece = pieces[i];
      if (!piece) return null;
      if (piece.includes(".")) {
        if (i !== pieces.length - 1) return null;
        const v4 = ipv4Parts(piece);
        if (!v4) return null;
        groups.push((v4[0] << 8) + v4[1], (v4[2] << 8) + v4[3]);
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return null;
      groups.push(Number.parseInt(piece, 16));
    }
    return groups;
  }

  if (doubleColonCount === 0) {
    const groups = parseSide(ip);
    return groups && groups.length === 8 ? groups : null;
  }

  const [leftRaw, rightRaw] = ip.split("::");
  const left = parseSide(leftRaw);
  const right = parseSide(rightRaw);
  if (!left || !right) return null;
  const missing = 8 - left.length - right.length;
  if (missing < 1) return null;
  return [...left, ...Array.from({ length: missing }, () => 0), ...right];
}

function isAllZero(groups: number[]): boolean {
  return groups.every((group) => group === 0);
}

function fallback(label: IpDisplayLabel, ip: string, scope: string, matchedCidr: string | null = null): IpDisplayClassification {
  return {
    ip,
    label,
    scope,
    matchedCidr,
    matchSource: "client_fallback",
    source: "fallback",
    isInternal: label === "Internal" || label === "Private" || label === "Loopback" || label === "Link-local" || label === "CGNAT",
    isPublic: label === "Public",
    isValid: label !== "Invalid" && Boolean(ip),
  };
}

export function classifyIpFallback(ip: string | null | undefined): IpDisplayClassification {
  const rawIp = clean(ip);
  if (!rawIp) return fallback("Unknown", "", "unknown");

  const v4 = ipv4Parts(rawIp);
  if (v4) {
    const [a, b, c] = v4;
    if (a === 127) return fallback("Loopback", rawIp, "loopback", "127.0.0.0/8");
    if (a === 169 && b === 254) return fallback("Link-local", rawIp, "link_local", "169.254.0.0/16");
    if (a === 100 && b >= 64 && b <= 127) return fallback("CGNAT", rawIp, "cgnat", "100.64.0.0/10");
    if (a === 10) return fallback("Private", rawIp, "private_address", "10.0.0.0/8");
    if (a === 172 && b >= 16 && b <= 31) return fallback("Private", rawIp, "private_address", "172.16.0.0/12");
    if (a === 192 && b === 168) return fallback("Private", rawIp, "private_address", "192.168.0.0/16");
    if (a === 192 && b === 0 && c === 2) return fallback("Reserved/Test", rawIp, "documentation", "192.0.2.0/24");
    if (a === 198 && b === 51 && c === 100) return fallback("Reserved/Test", rawIp, "documentation", "198.51.100.0/24");
    if (a === 203 && b === 0 && c === 113) return fallback("Reserved/Test", rawIp, "documentation", "203.0.113.0/24");
    if (a === 198 && (b === 18 || b === 19)) return fallback("Reserved/Test", rawIp, "reserved", "198.18.0.0/15");
    if (a === 0) return fallback("Reserved/Test", rawIp, "unspecified", "0.0.0.0/8");
    if (a >= 224) return fallback("Reserved/Test", rawIp, "reserved", a < 240 ? "224.0.0.0/4" : "240.0.0.0/4");
    return fallback("Public", rawIp, "public_internet");
  }

  const v6 = parseIpv6Groups(rawIp);
  if (!v6) return fallback("Invalid", rawIp, "invalid");

  if (isAllZero(v6)) return fallback("Reserved/Test", rawIp, "unspecified", "::/128");
  if (v6.slice(0, 7).every((group) => group === 0) && v6[7] === 1) return fallback("Loopback", rawIp, "loopback", "::1/128");
  if ((v6[0] & 0xffc0) === 0xfe80) return fallback("Link-local", rawIp, "link_local", "fe80::/10");
  if ((v6[0] & 0xfe00) === 0xfc00) return fallback("Private", rawIp, "unique_local", "fc00::/7");
  if (v6[0] === 0x2001 && v6[1] === 0x0db8) return fallback("Reserved/Test", rawIp, "documentation", "2001:db8::/32");
  if ((v6[0] & 0xff00) === 0xff00) return fallback("Reserved/Test", rawIp, "multicast", "ff00::/8");
  if ((v6[0] & 0xe000) !== 0x2000) return fallback("Reserved/Test", rawIp, "reserved");
  return fallback("Public", rawIp, "public_internet");
}

export function resolveIpClassification(ip: string | null | undefined, ipContext?: IpContextInput): IpDisplayClassification {
  const rawIp = clean(ip);
  const backend = fromBackendContext(rawIp, inferFlowIpContext(ipContext, rawIp));
  if (backend) return backend;
  return classifyIpFallback(rawIp);
}

export function ipClassificationTitle(classification: IpDisplayClassification): string {
  const parts = [`scope: ${classification.scope || classification.label}`];
  if (classification.matchedCidr) parts.push(`matched CIDR: ${classification.matchedCidr}`);
  parts.push(`match source: ${classification.matchSource || classification.source}`);
  return parts.join(" · ");
}
