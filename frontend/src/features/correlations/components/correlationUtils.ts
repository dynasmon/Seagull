import type { SeverityVariant } from "@/shared/components/SeverityPill";
import type { StatusVariant } from "@/shared/components/StatusPill";

import type {
  CorrelationConfidence,
  CorrelationContext,
  CorrelationEntityType,
  CorrelationEntityValue,
  CorrelationEvidence,
  CorrelationIncidentDetail,
  CorrelationMitreMetadata,
  CorrelationRiskScore,
  CorrelationRunIncident,
} from "../types";

type MitreSource =
  | Pick<CorrelationIncidentDetail, "context" | "evidence">
  | Pick<CorrelationRunIncident, "context" | "evidence_items">
  | null
  | undefined;

const TECHNIQUE_ID_RE = /^T\d{4}(?:\.\d{3})?$/i;

export function correlationSeverityVariant(value?: string | null): SeverityVariant {
  const severity = String(value || "").trim().toLowerCase();
  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (severity === "medium") return "medium";
  if (severity === "low") return "low";
  if (severity === "info") return "info";
  return "neutral";
}

export function correlationStatusVariant(value?: string | null): StatusVariant {
  const status = String(value || "").trim().toLowerCase();
  if (status === "open") return "active";
  if (status === "triaged") return "pending";
  if (status === "suppressed") return "warning";
  if (status === "closed") return "inactive";
  return "neutral";
}

export function correlationRiskVariant(value?: number | null): SeverityVariant {
  if (value === null || value === undefined) return "neutral";
  if (value >= 85) return "critical";
  if (value >= 70) return "high";
  if (value >= 45) return "medium";
  if (value > 0) return "low";
  return "neutral";
}

export function correlationConfidenceVariant(value?: number | null): SeverityVariant {
  if (value === null || value === undefined) return "neutral";
  if (value >= 85) return "high";
  if (value >= 65) return "medium";
  if (value > 0) return "low";
  return "neutral";
}

export function correlationEntityLabel(
  entityType: CorrelationEntityType,
  entityValue: CorrelationEntityValue,
  groupBy?: string | null,
  groupValue?: string | null,
) {
  return {
    type: String(entityType || groupBy || "entity"),
    value: String(entityValue || groupValue || "-"),
  };
}

function normalizeText(value: unknown): string | null {
  const text = String(value ?? "").trim();
  return text ? text : null;
}

function formatTacticLabel(value: string): string {
  return value
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function pushTactic(store: Map<string, string>, value: unknown) {
  const text = normalizeText(value);
  if (!text) return;
  const key = text.toLowerCase();
  if (!store.has(key)) store.set(key, formatTacticLabel(text));
}

function pushTechnique(store: Map<string, { id: string; name?: string | null }>, idValue: unknown, nameValue?: unknown) {
  const rawId = normalizeText(idValue);
  if (!rawId) return;
  const normalizedId = TECHNIQUE_ID_RE.test(rawId) ? rawId.toUpperCase() : rawId;
  const normalizedName = normalizeText(nameValue);
  const existing = store.get(normalizedId);
  if (existing) {
    if (!existing.name && normalizedName) existing.name = normalizedName;
    return;
  }
  store.set(normalizedId, {
    id: normalizedId,
    name: normalizedName,
  });
}

function collectMitreFromContext(
  node: unknown,
  tactics: Map<string, string>,
  techniques: Map<string, { id: string; name?: string | null }>,
  depth = 0,
  insideMitre = false,
) {
  if (node === null || node === undefined || depth > 5) return;

  if (Array.isArray(node)) {
    for (const item of node) collectMitreFromContext(item, tactics, techniques, depth + 1, insideMitre);
    return;
  }

  if (typeof node !== "object") return;
  const record = node as Record<string, unknown>;

  pushTactic(tactics, record.mitre_tactic);
  pushTactic(tactics, record.attack_tactic);
  if (Array.isArray(record.mitre_tactics)) {
    for (const item of record.mitre_tactics) pushTactic(tactics, item);
  }

  pushTechnique(techniques, record.technique_id, record.technique_name ?? record.name);
  pushTechnique(techniques, record.mitre_technique_id, record.mitre_technique_name ?? record.name);
  if (TECHNIQUE_ID_RE.test(String(record.mitre_technique ?? "").trim())) {
    pushTechnique(techniques, record.mitre_technique, record.mitre_technique_name ?? record.name);
  }

  if (insideMitre) {
    pushTactic(tactics, record.tactic);
    if (Array.isArray(record.tactics)) {
      for (const item of record.tactics) pushTactic(tactics, item);
    }

    pushTechnique(techniques, record.id, record.name);
    pushTechnique(techniques, record.technique, record.name);
    if (Array.isArray(record.techniques)) {
      for (const item of record.techniques) collectMitreFromContext(item, tactics, techniques, depth + 1, true);
    }
  }

  if (record.mitre) collectMitreFromContext(record.mitre, tactics, techniques, depth + 1, true);
  if (record.mitre_techniques) collectMitreFromContext(record.mitre_techniques, tactics, techniques, depth + 1, true);
}

function evidenceItems(source: MitreSource): CorrelationEvidence[] {
  if (!source) return [];
  if ("evidence" in source) return Array.isArray(source.evidence) ? source.evidence : [];
  if ("evidence_items" in source) return Array.isArray(source.evidence_items) ? source.evidence_items : [];
  return [];
}

function contextOf(source: MitreSource): CorrelationContext {
  if (!source || typeof source.context !== "object" || source.context === null) return {};
  return source.context;
}

export function extractCorrelationMitreMetadata(source: MitreSource): CorrelationMitreMetadata {
  const tactics = new Map<string, string>();
  const techniques = new Map<string, { id: string; name?: string | null }>();

  collectMitreFromContext(contextOf(source), tactics, techniques, 0, false);
  for (const item of evidenceItems(source)) {
    collectMitreFromContext(item.details, tactics, techniques, 0, false);
  }

  return {
    tactics: Array.from(tactics.values()),
    techniques: Array.from(techniques.values()),
  };
}

export function hasCorrelationMitreMetadata(metadata: CorrelationMitreMetadata | null | undefined) {
  return Boolean(metadata && (metadata.tactics.length > 0 || metadata.techniques.length > 0));
}

export function correlationMitrePreview(metadata: CorrelationMitreMetadata, limit = 2): string[] {
  const tactics = metadata.tactics.slice(0, limit);
  const techniques = metadata.techniques.slice(0, limit).map((item) => item.id);
  return [...tactics, ...techniques].slice(0, limit * 2);
}

function detailText(details: Record<string, unknown>, key: string) {
  const value = details[key];
  if (value === null || value === undefined || value === "") return null;
  if (Array.isArray(value)) {
    const items = value.map((item) => String(item || "").trim()).filter(Boolean);
    return items.length > 0 ? items.join(", ") : null;
  }
  return String(value);
}

function evidenceTypeLabel(value: string) {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "net_event") return "Net event";
  if (normalized === "exposure_finding") return "Exposure finding";
  if (normalized === "attack_chain_step") return "Attack chain step";
  if (normalized === "attack_chain_case") return "Attack chain case";
  if (normalized === "vulnerability") return "Vulnerability";
  if (normalized === "alert") return "Alert";
  return value || "Evidence";
}

export function isCorrelationAlertEvidence(item: CorrelationEvidence) {
  return String(item.evidence_type || "").toLowerCase() === "alert";
}

export function isCorrelationNetEventEvidence(item: CorrelationEvidence) {
  const evidenceType = String(item.evidence_type || "").toLowerCase();
  return evidenceType === "net_event" || (evidenceType !== "alert" && item.net_event_id !== null && item.net_event_id !== undefined);
}

export function correlationEvidenceTitle(item: CorrelationEvidence) {
  const details = item.details || {};
  return (
    detailText(details, "description")
    || detailText(details, "label")
    || detailText(details, "event_type")
    || detailText(details, "finding_key")
    || detailText(details, "cve")
    || `${evidenceTypeLabel(item.evidence_type)}${item.alert_id ? ` #${item.alert_id}` : item.net_event_id ? ` #${item.net_event_id}` : ""}`
  );
}

export function correlationEvidenceDescription(item: CorrelationEvidence) {
  const details = item.details || {};
  const parts = [
    detailText(details, "kind"),
    detailText(details, "agent_id"),
    detailText(details, "asset_key"),
    detailText(details, "finding_id"),
    detailText(details, "case_id"),
  ].filter(Boolean);
  return parts.length > 0 ? parts.join(" · ") : undefined;
}

export function formatCorrelationScoreLabel(score: CorrelationRiskScore, label = "Risk") {
  return score === null || score === undefined ? `${label} -` : `${label} ${score}`;
}

export function formatCorrelationConfidenceLabel(confidence: CorrelationConfidence) {
  return confidence === null || confidence === undefined ? "Confidence -" : `Confidence ${confidence}%`;
}
