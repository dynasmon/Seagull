import type { CursorPage } from "@/shared/types/pagination";

export type AttackChainCaseStatus = "open" | "closed" | string;

export type AttackChainCase = {
  id: number;
  agent_id: string;
  suspect_ip: string | null;
  status: AttackChainCaseStatus;
  score: number;
  max_stage: string;
  first_seen_at: string;
  last_seen_at: string;
  closed_at?: string | null;
  step_count: number;
  context?: any;
};

export type AttackChainStep = {
  id: number;
  case_id: number;
  stage: string;
  fingerprint: string;
  score_delta: number;
  label: string;

  event_id?: number | null;
  event_type?: string | null;

  timestamp: string;
  created_at: string;

  src_ip?: string | null;
  dst_ip?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  proto?: string | null;

  details: any;
};

export type MitreTechniqueStat = {
  technique_id: string;
  technique?: string | null;
  count: number;
  max_confidence: number;
  avg_confidence: number;
};

export type MitreTacticCoverage = {
  tactic: string;
  total: number;
  max_confidence: number;
  avg_confidence: number;
  techniques: MitreTechniqueStat[];
};

export type MitreCaseSummary = {
  progression: string[];
  tactics: MitreTacticCoverage[];
};

export type AttackChainCaseWithSteps = {
  case: AttackChainCase;
  steps: AttackChainStep[];
  mitre: MitreCaseSummary;
};

export type AttackChainCasesPage = CursorPage<AttackChainCase>;
