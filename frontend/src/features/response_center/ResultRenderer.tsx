import { InvestigationRawJsonPanel } from "@/shared/components/investigation";

import BlockIpResultRenderer from "./renderers/BlockIpResultRenderer";
import KillProcessResultRenderer from "./renderers/KillProcessResultRenderer";
import QuarantineFileResultRenderer from "./renderers/QuarantineFileResultRenderer";
import ShellExecResultRenderer from "./renderers/ShellExecResultRenderer";
import TriageBundleResultRenderer from "./renderers/TriageBundleResultRenderer";
import type { ResponseActionResultOut } from "./types";

export interface ResultPivotInput {
  actionKey: string;
  agentId?: string;
  payload?: Record<string, any>;
}

interface ResultRendererProps {
  actionType: string;
  result: ResponseActionResultOut;
  requestPayload?: Record<string, any> | null;
  onPivot?: (input: ResultPivotInput) => void;
}

export default function ResultRenderer({ actionType, result, requestPayload, onPivot }: ResultRendererProps) {
  switch (actionType) {
    case "collect_triage_bundle":
      return <TriageBundleResultRenderer result={result} />;
    case "kill_process":
      return <KillProcessResultRenderer result={result} />;
    case "block_outbound_ip":
    case "unblock_outbound_ip":
      return <BlockIpResultRenderer actionType={actionType} result={result} requestPayload={requestPayload} onPivot={onPivot} />;
    case "quarantine_file":
      return <QuarantineFileResultRenderer result={result} />;
    case "run_shell_command":
      return <ShellExecResultRenderer result={result} />;
    default:
      return <InvestigationRawJsonPanel value={result.result_payload} title="Result payload" />;
  }
}
