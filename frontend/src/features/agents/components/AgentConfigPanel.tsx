import EmptyState from "@/shared/components/EmptyState";
import { Panel } from "@/shared/components/Panel";
import { TextArea } from "@/shared/components/TextArea";
import { TextInput } from "@/shared/components/TextInput";
import { ToggleSwitch } from "@/shared/components/ToggleSwitch";
import { cx } from "@/shared/lib/cx";

import { FieldLabel } from "./AgentsPageShared";
import type { DdosConfigDraft } from "../lib/agentUtils";
import { safeJsonParse, prettyJson } from "../lib/agentUtils";

interface AgentConfigPanelProps {
  configObj: Record<string, any>;
  configText: string;
  configParseError: string | null;
  ddosDraft: DdosConfigDraft;
  timingKeys: string[];
  configBusy: boolean;
  onConfigTextChange: (v: string) => void;
  onUpdateTiming: (key: string, value: number) => void;
  onApplyDdosConfig: () => Promise<void>;
  onApplyConfig: () => Promise<void>;
  setDdosDraft: (updater: (prev: DdosConfigDraft) => DdosConfigDraft) => void;
  setConfigText: (v: string) => void;
}

export default function AgentConfigPanel({
  configObj,
  configText,
  configParseError,
  ddosDraft,
  timingKeys,
  configBusy,
  onConfigTextChange,
  onUpdateTiming,
  onApplyDdosConfig,
  onApplyConfig,
  setDdosDraft,
  setConfigText,
}: AgentConfigPanelProps) {
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Panel title="DDoS / Backpressure">
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <ToggleSwitch
              checked={ddosDraft.enabled}
              onChange={(e) => setDdosDraft((s) => ({ ...s, enabled: e.target.checked }))}
              disabled={configBusy}
              label="DDoS module"
            />
            <ToggleSwitch
              checked={ddosDraft.enable_l7}
              onChange={(e) => setDdosDraft((s) => ({ ...s, enable_l7: e.target.checked }))}
              disabled={configBusy}
              label="L7 detection"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel>Interface</FieldLabel>
              <TextInput
                className="mt-1 font-mono text-[11px]"
                value={ddosDraft.iface}
                onChange={(e) => setDdosDraft((s) => ({ ...s, iface: e.target.value }))}
                placeholder="any / eth0"
                disabled={configBusy}
              />
            </div>
            <div>
              <FieldLabel>Window</FieldLabel>
              <TextInput
                className="mt-1 font-mono text-[11px]"
                value={ddosDraft.window}
                onChange={(e) => setDdosDraft((s) => ({ ...s, window: e.target.value }))}
                placeholder="1s"
                disabled={configBusy}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel>Eval Every</FieldLabel>
              <TextInput
                className="mt-1 font-mono text-[11px]"
                value={ddosDraft.eval_every}
                onChange={(e) => setDdosDraft((s) => ({ ...s, eval_every: e.target.value }))}
                placeholder="1s"
                disabled={configBusy}
              />
            </div>
            <div>
              <FieldLabel>Cooldown</FieldLabel>
              <TextInput
                className="mt-1 font-mono text-[11px]"
                value={ddosDraft.cooldown}
                onChange={(e) => setDdosDraft((s) => ({ ...s, cooldown: e.target.value }))}
                placeholder="30s"
                disabled={configBusy}
              />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <FieldLabel>Sustain</FieldLabel>
              <TextInput
                type="number"
                className="mt-1 font-mono text-[11px]"
                value={String(ddosDraft.sustain_windows)}
                onChange={(e) => setDdosDraft((s) => ({ ...s, sustain_windows: Number(e.target.value) || 1 }))}
                disabled={configBusy}
              />
            </div>
            <div>
              <FieldLabel>Min Confidence</FieldLabel>
              <TextInput
                type="number"
                className="mt-1 font-mono text-[11px]"
                value={String(ddosDraft.min_confidence)}
                onChange={(e) => setDdosDraft((s) => ({ ...s, min_confidence: Number(e.target.value) || 1 }))}
                disabled={configBusy}
              />
            </div>
            <div>
              <FieldLabel>Max Batch</FieldLabel>
              <TextInput
                type="number"
                className="mt-1 font-mono text-[11px]"
                value={String(ddosDraft.max_batch)}
                onChange={(e) => setDdosDraft((s) => ({ ...s, max_batch: Number(e.target.value) || 1 }))}
                disabled={configBusy}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel>Min PPS</FieldLabel>
              <TextInput
                type="number"
                className="mt-1 font-mono text-[11px]"
                value={String(ddosDraft.min_pps)}
                onChange={(e) => setDdosDraft((s) => ({ ...s, min_pps: Number(e.target.value) || 0 }))}
                disabled={configBusy}
              />
            </div>
            <div>
              <FieldLabel>Min BPS</FieldLabel>
              <TextInput
                type="number"
                className="mt-1 font-mono text-[11px]"
                value={String(ddosDraft.min_bps)}
                onChange={(e) => setDdosDraft((s) => ({ ...s, min_bps: Number(e.target.value) || 0 }))}
                disabled={configBusy}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel>Min HTTP RPS</FieldLabel>
              <TextInput
                type="number"
                className="mt-1 font-mono text-[11px]"
                value={String(ddosDraft.min_http_rps)}
                onChange={(e) => setDdosDraft((s) => ({ ...s, min_http_rps: Number(e.target.value) || 0 }))}
                disabled={configBusy}
              />
            </div>
            <div>
              <FieldLabel>Min TLS HS RPS</FieldLabel>
              <TextInput
                type="number"
                className="mt-1 font-mono text-[11px]"
                value={String(ddosDraft.min_tls_hs_rps)}
                onChange={(e) => setDdosDraft((s) => ({ ...s, min_tls_hs_rps: Number(e.target.value) || 0 }))}
                disabled={configBusy}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel>BP High Watermark</FieldLabel>
              <TextInput
                type="number"
                className="mt-1 font-mono text-[11px]"
                value={String(ddosDraft.backpressure_high_watermark)}
                onChange={(e) =>
                  setDdosDraft((s) => ({ ...s, backpressure_high_watermark: Number(e.target.value) || 1 }))
                }
                disabled={configBusy}
              />
            </div>
            <div>
              <FieldLabel>BP Sample Every</FieldLabel>
              <TextInput
                type="number"
                className="mt-1 font-mono text-[11px]"
                value={String(ddosDraft.backpressure_sample_every)}
                onChange={(e) =>
                  setDdosDraft((s) => ({ ...s, backpressure_sample_every: Number(e.target.value) || 1 }))
                }
                disabled={configBusy}
              />
            </div>
          </div>

          <div className="text-[11px] text-muted-foreground">
            These settings are saved in agent config (`modules.ddos`) and replace the need to edit `.env` for DDoS tuning.
            Restart the agent container to apply capture-level changes.
          </div>

          <button
            type="button"
            onClick={onApplyDdosConfig}
            disabled={configBusy}
            className={cx(
              "w-full border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
              "hover:bg-primary/5",
              configBusy && "opacity-60 cursor-not-allowed"
            )}
          >
            {configBusy ? "Saving..." : "Save DDoS settings"}
          </button>
        </div>
      </Panel>

      <Panel title="Timings" actions={<span className="text-[10px] font-mono text-muted-foreground">{timingKeys.length ? `${timingKeys.length} keys` : "-"}</span>}>
        {timingKeys.length === 0 ? (
          <EmptyState title="No timing keys" hint="This agent config does not expose timing-related fields." />
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            {timingKeys.map((k) => (
              <div key={k}>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{k}</div>
                <TextInput
                  type="number"
                  className="mt-1 font-mono text-[11px]"
                  value={String((configObj as any)[k] ?? "")}
                  onChange={(e) => onUpdateTiming(k, Number(e.target.value))}
                  disabled={configBusy}
                />
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel title="Raw config" actions={<span className="text-[10px] font-mono text-muted-foreground">{configParseError ? "Invalid" : "JSON"}</span>}>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <FieldLabel>Config (JSON)</FieldLabel>
            <button
              type="button"
              onClick={() => {
                const parsed = safeJsonParse(configText);
                if (parsed.ok) setConfigText(prettyJson(parsed.value));
              }}
              className="text-[10px] text-primary hover:underline"
            >
              Format
            </button>
          </div>

          <TextArea
            className="mt-1 font-mono text-[11px]"
            rows={14}
            value={configText}
            onChange={(e) => onConfigTextChange(e.target.value)}
            disabled={configBusy}
          />

          {configParseError && <div className="text-[11px] text-danger">Config: {configParseError}</div>}

          <button
            type="button"
            onClick={onApplyConfig}
            disabled={configBusy || Boolean(configParseError)}
            className={cx(
              "w-full border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
              "hover:bg-primary/5",
              (configBusy || Boolean(configParseError)) && "opacity-60 cursor-not-allowed"
            )}
          >
            {configBusy ? "Pushing..." : "Push config"}
          </button>
        </div>
      </Panel>
    </div>
  );
}
