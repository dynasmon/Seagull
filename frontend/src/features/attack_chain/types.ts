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
  reasoning?: {
    generated_at?: string;
    overall?: {
      verdict?: string;
      analyst_hint?: string;
      quality_counts?: {
        observed?: number;
        strongly_supported?: number;
        inferred?: number;
        weakly_inferred?: number;
      };
      stage_count?: number;
    };
    stages?: Array<{
      stage: string;
      label?: string;
      support_level?: "observed" | "strongly_supported" | "inferred" | "weakly_inferred" | string;
      confidence?: number;
      support_score?: number;
      direct_support?: number;
      inferred_support?: number;
      evidence_count?: number;
      observed_count?: number;
      strong_count?: number;
      inferred_count?: number;
      weak_count?: number;
      direct_count?: number;
      inferred_nature_count?: number;
      families?: string[];
      top_factors?: string[];
      missing_evidence?: string[];
      promoted?: boolean;
      transition?: {
        allowed?: boolean;
        promoted?: boolean;
        reason?: string;
      };
    }>;
  };
};

export type AttackChainCasesPage = CursorPage<AttackChainCase>;
