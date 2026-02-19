export type StageKey =
  | "initial_access"
  | "execution"
  | "persistence"
  | "privilege_escalation"
  | "defense_evasion"
  | "command_and_control"
  | "exfiltration";

export const STAGES: Array<{ key: StageKey; label: string; hint: string }> = [
  {
    key: "initial_access",
    label: "Initial Access",
    hint: "SSH brute force, credential stuffing, exposed services"
  },
  {
    key: "execution",
    label: "Execution",
    hint: "LOLBins, suspicious process execution, remote command"
  },
  {
    key: "persistence",
    label: "Persistence",
    hint: "cron/systemd hooks, authorized_keys changes, new users"
  },
  {
    key: "privilege_escalation",
    label: "Privilege Escalation",
    hint: "sudo abuse, pkexec, capabilities, SUID anomalies"
  },
  {
    key: "defense_evasion",
    label: "Defense Evasion",
    hint: "log tampering, disabling agents/services, clearing history"
  },
  {
    key: "command_and_control",
    label: "Command & Control",
    hint: "beaconing patterns, suspicious outbound control traffic"
  },
  {
    key: "exfiltration",
    label: "Exfiltration",
    hint: "anomalous egress, high-volume transfer, uncommon destinations"
  }
];

export function normalizeStage(stage: string): StageKey | "unknown" {
  const s = String(stage || "").trim();
  const hit = STAGES.find((x) => x.key === s);
  return hit ? hit.key : "unknown";
}

export function stageLabel(stage: string): string {
  const k = normalizeStage(stage);
  const hit = STAGES.find((x) => x.key === k);
  return hit ? hit.label : String(stage || "unknown");
}

export function stageRank(stage: string): number {
  const k = normalizeStage(stage);
  const idx = STAGES.findIndex((x) => x.key === k);
  return idx < 0 ? 0 : idx;
}
