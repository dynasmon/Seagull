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
  timestamp: string;
  kind: string;
  title: string;
  description: string;
  fingerprint: string;
  score_delta: number;
  details: any;
  created_at: string;
};

export type AttackChainCaseWithSteps = {
  case: AttackChainCase;
  steps: AttackChainStep[];
};

export type AttackChainCasesPage = CursorPage<AttackChainCase>;
