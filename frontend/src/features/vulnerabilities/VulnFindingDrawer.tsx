import { useMemo, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import Drawer from "@/shared/components/Drawer";
import { cx } from "@/shared/lib/cx";

import { patchVulnFinding } from "./api";
import type { VulnFinding } from "./types";

function sevVariant(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "neutral";
}

function fmtWhen(iso?: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

function safeJson(v: any): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

function ActionButton(props: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  kind?: "primary" | "danger" | "neutral";
}) {
  const kind = props.kind ?? "neutral";
  const base =
    "inline-flex items-center justify-center rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest";
  const klass =
    kind === "primary"
      ? "text-foreground hover:bg-primary/15 focus:ring-primary/30"
      : kind === "danger"
        ? "text-red-400 hover:bg-red-500/10 focus:ring-red-500/30"
        : "text-muted-foreground hover:bg-muted/15 hover:text-foreground focus:ring-primary/30";

  return (
    <button
      type="button"
      disabled={props.disabled}
      onClick={props.onClick}
      className={cx(base, klass, "focus:outline-none focus:ring-2", props.disabled && "opacity-60")}
    >
      {props.label}
    </button>
  );
}

export default function VulnFindingDrawer(props: {
  open: boolean;
  finding: VulnFinding | null;
  onClose: () => void;
  onPatched: (next: VulnFinding) => void;
}) {
  const f = props.finding;

  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const title = useMemo(() => {
    if (!f) return "Vulnerability";
    const base = f.cve ? `${f.cve} — ${f.title}` : f.title;
    return base.length > 120 ? `${base.slice(0, 117)}…` : base;
  }, [f]);

  async function doPatch(patch: { status?: string; is_suppressed?: boolean }) {
    if (!f || busy) return;
    setBusy(true);
    setErr(null);
    try {
      const next = await patchVulnFinding(f.id, patch);
      props.onPatched(next);
    } catch (e: any) {
      setErr(e?.message || "Failed to update");
    } finally {
      setBusy(false);
    }
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      // Ignore: clipboard permission can be denied.
    }
  }

  return (
    <Drawer
      open={props.open}
      title={title}
      description={f ? `Finding #${f.id} • ${f.source} • Last seen ${fmtWhen(f.last_seen_at)}` : ""}
      onClose={props.onClose}
      widthClassName="w-[820px]"
    >
      {!f ? (
        <div className="text-sm text-muted-foreground">No finding selected.</div>
      ) : (
        <div className="space-y-5">
          {/* Header */}
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={sevVariant(f.severity)}>{f.severity}</Badge>
            <Badge variant={f.status === "open" ? "info" : "neutral"}>{f.status}</Badge>
            {f.is_suppressed ? <Badge variant="neutral">suppressed</Badge> : null}
            <span className="text-xs text-muted-foreground">confidence {f.confidence}/100</span>
          </div>

          {/* Actions */}
          <div className="flex flex-wrap gap-2">
            <ActionButton
              label={f.status === "open" ? "Mark Fixed" : "Reopen"}
              kind="primary"
              disabled={busy}
              onClick={() => doPatch({ status: f.status === "open" ? "fixed" : "open" })}
            />
            <ActionButton
              label={f.is_suppressed ? "Unsuppress" : "Suppress"}
              kind={f.is_suppressed ? "neutral" : "danger"}
              disabled={busy}
              onClick={() => doPatch({ is_suppressed: !f.is_suppressed })}
            />
            <ActionButton
              label={copied ? "Copied" : "Copy fingerprint"}
              disabled={!f.fingerprint}
              onClick={() => copy(f.fingerprint)}
            />
          </div>

          {err ? (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">
              {err}
            </div>
          ) : null}

          {/* Main fields */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="rounded-xl border border-border/60 bg-background/60 backdrop-blur-md p-4">
              <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Asset</div>
              <div className="mt-2 space-y-2">
                <div className="text-sm">
                  <div className="text-xs text-muted-foreground">asset_key</div>
                  <div className="font-mono text-[12px] break-all">{f.asset_key}</div>
                </div>
                <div className="text-sm">
                  <div className="text-xs text-muted-foreground">reporter_agent_id</div>
                  <div className="font-mono text-[12px] break-all">{f.reporter_agent_id || "-"}</div>
                </div>
                <div className="text-sm">
                  <div className="text-xs text-muted-foreground">location</div>
                  <div className="font-mono text-[12px] break-all">{f.location || "-"}</div>
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-border/60 bg-background/60 backdrop-blur-md p-4">
              <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Timing</div>
              <div className="mt-2 space-y-2">
                <div className="text-sm">
                  <div className="text-xs text-muted-foreground">first_seen</div>
                  <div className="font-mono text-[12px]">{fmtWhen(f.first_seen_at)}</div>
                </div>
                <div className="text-sm">
                  <div className="text-xs text-muted-foreground">last_seen</div>
                  <div className="font-mono text-[12px]">{fmtWhen(f.last_seen_at)}</div>
                </div>
                <div className="text-sm">
                  <div className="text-xs text-muted-foreground">occurrences</div>
                  <div className="font-mono text-[12px]">{f.occurrences}</div>
                </div>
              </div>
            </div>
          </div>

          {/* Identifiers */}
          <div className="rounded-xl border border-border/60 bg-background/60 backdrop-blur-md p-4">
            <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Identifiers</div>
            <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
              <div>
                <div className="text-xs text-muted-foreground">CVE</div>
                <div className="font-mono text-[12px] break-all">{f.cve || "-"}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground">external_id</div>
                <div className="font-mono text-[12px] break-all">{f.external_id || "-"}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground">source</div>
                <div className="font-mono text-[12px] break-all">{f.source}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground">fingerprint</div>
                <div className="font-mono text-[12px] break-all">{f.fingerprint}</div>
              </div>
            </div>
          </div>

          {/* Description / remediation */}
          {f.description || f.remediation ? (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div className="rounded-xl border border-border/60 bg-background/60 backdrop-blur-md p-4">
                <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Description</div>
                <div className="mt-2 text-sm text-foreground/90 whitespace-pre-wrap">{f.description || "-"}</div>
              </div>
              <div className="rounded-xl border border-border/60 bg-background/60 backdrop-blur-md p-4">
                <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Remediation</div>
                <div className="mt-2 text-sm text-foreground/90 whitespace-pre-wrap">{f.remediation || "-"}</div>
              </div>
            </div>
          ) : null}

          {/* Tags */}
          <div className="rounded-xl border border-border/60 bg-background/60 backdrop-blur-md p-4">
            <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Tags</div>
            <div className="mt-2 flex flex-wrap gap-2">
              {f.tags?.length ? (
                f.tags.map((t) => (
                  <span key={t} className="inline-flex items-center rounded-md border border-border/60 bg-background/30 px-2 py-0.5 text-[11px] font-mono">
                    {t}
                  </span>
                ))
              ) : (
                <span className="text-sm text-muted-foreground">-</span>
              )}
            </div>
          </div>

          {/* Evidence */}
          <div className="rounded-xl border border-border/60 bg-background/60 backdrop-blur-md p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Evidence</div>
              <button
                type="button"
                className={cx(
                  "rounded-md border border-border/60 bg-background/40 px-3 py-2",
                  "text-xs font-mono uppercase tracking-widest text-muted-foreground",
                  "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
                )}
                onClick={() => copy(safeJson(f.evidence || {}))}
              >
                {copied ? "Copied" : "Copy JSON"}
              </button>
            </div>
            <pre className="mt-3 max-h-[320px] overflow-auto rounded-lg border border-border/60 bg-background/40 p-3 text-[12px] text-foreground/90">
              {safeJson(f.evidence || {})}
            </pre>
          </div>

          {/* Asset metadata */}
          {f.asset && Object.keys(f.asset).length ? (
            <div className="rounded-xl border border-border/60 bg-background/60 backdrop-blur-md p-4">
              <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Asset metadata</div>
              <pre className="mt-3 max-h-[220px] overflow-auto rounded-lg border border-border/60 bg-background/40 p-3 text-[12px] text-foreground/90">
                {safeJson(f.asset)}
              </pre>
            </div>
          ) : null}
        </div>
      )}
    </Drawer>
  );
}
