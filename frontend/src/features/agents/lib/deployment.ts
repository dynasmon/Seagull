import type {
  AgentArchitecture,
  AgentEnrollmentTicketIn,
  AgentPackageState,
  AgentProfile,
} from "../types";

const AGENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const BASE64_OVERHEAD = 4 / 3;

export interface DeploymentTarget {
  agentId: string;
  profile: AgentProfile;
  architecture: AgentArchitecture;
  sources: string[];
}

export function isValidAgentId(value: string): boolean {
  return AGENT_ID_PATTERN.test(value.trim());
}

export function toggleCollector(current: string[], name: string, catalog: string[]): string[] {
  const selected = new Set(current);
  if (selected.has(name)) selected.delete(name);
  else selected.add(name);
  return catalog.filter((entry) => selected.has(entry));
}

export function packageFor(
  packages: AgentPackageState[],
  architecture: AgentArchitecture,
): AgentPackageState | null {
  return packages.find((entry) => entry.architecture === architecture) ?? null;
}

export function installerSizeBytes(packageSizeBytes: number): number {
  return Math.round(packageSizeBytes * BASE64_OVERHEAD);
}

export function ticketRequestFrom(target: DeploymentTarget): AgentEnrollmentTicketIn {
  return {
    agent_id: target.agentId.trim(),
    profile: target.profile,
    architecture: target.architecture,
    sources: target.sources,
  };
}

export function canIssueTicket(target: DeploymentTarget, { isAdmin, busy }: { isAdmin: boolean; busy: boolean }): boolean {
  return isAdmin && !busy && isValidAgentId(target.agentId) && target.sources.length > 0;
}
