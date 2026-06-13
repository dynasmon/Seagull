import { EuiCodeBlock } from "@elastic/eui";

import { Badge } from "@/shared/components/Badge";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { StatusPill } from "@/shared/components/StatusPill";

import type { ResponseActionResultOut } from "../types";
import { DetailRow } from "./lib";

export default function ShellExecResultRenderer({ result }: { result: ResponseActionResultOut }) {
  const payload = result.result_payload || {};
  const command = typeof payload.command === "string" ? payload.command : "";
  const exitCode = typeof payload.exit_code === "number" ? payload.exit_code : null;
  const stdout = typeof payload.stdout === "string" ? payload.stdout : "";
  const stderr = typeof payload.stderr === "string" ? payload.stderr : "";
  const timedOut = Boolean(payload.timed_out);
  const durationMs = typeof payload.duration_ms === "number" ? payload.duration_ms : null;
  const workingDir = typeof payload.working_dir === "string" ? payload.working_dir : "";
  const succeeded = exitCode === 0 && !timedOut;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <StatusPill variant={succeeded ? "success" : "danger"}>exit {exitCode === null ? "—" : exitCode}</StatusPill>
        {timedOut ? <Badge variant="high">timed out</Badge> : null}
        {durationMs !== null ? <Badge variant="neutral">{durationMs} ms</Badge> : null}
      </div>

      {command ? (
        <div>
          <div className="mb-1 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">Command</div>
          <EuiCodeBlock language="bash" fontSize="s" paddingSize="s" isCopyable>
            {command}
          </EuiCodeBlock>
        </div>
      ) : null}

      {workingDir ? (
        <DetailRow label="Working dir">
          <span className="font-mono text-[12px]">{workingDir}</span>
        </DetailRow>
      ) : null}

      {timedOut ? <InlineAlert tone="danger">Command exceeded its timeout and was terminated.</InlineAlert> : null}

      <div>
        <div className="mb-1 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">stdout</div>
        {stdout ? (
          <EuiCodeBlock language="text" fontSize="s" paddingSize="s" overflowHeight={280} isCopyable>
            {stdout}
          </EuiCodeBlock>
        ) : (
          <div className="text-[12px] text-muted-foreground">No output.</div>
        )}
      </div>

      <div>
        <div className="mb-1 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">stderr</div>
        {stderr ? (
          <EuiCodeBlock language="text" fontSize="s" paddingSize="s" overflowHeight={280} isCopyable>
            {stderr}
          </EuiCodeBlock>
        ) : (
          <div className="text-[12px] text-muted-foreground">No output.</div>
        )}
      </div>
    </div>
  );
}
