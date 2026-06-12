import { apiGet, apiPost } from "@/shared/lib/http";
import type { ApiGetOptions } from "@/shared/lib/http";

import type {
  ActionTypeOut,
  BatchDispatchIn,
  BatchDispatchOut,
  ResponseActionCreateIn,
  ResponseActionListParams,
  ResponseActionOut,
  ResponseActionResultOut,
  TimelineEventOut,
} from "./types";

export function listActionTypes(opts?: ApiGetOptions) {
  return apiGet<ActionTypeOut[]>("/api/response/action-types", opts);
}

export function listResponseActions(params?: ResponseActionListParams, opts?: ApiGetOptions) {
  const q = new URLSearchParams();
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.agent_ids?.length) q.set("agent_ids", params.agent_ids.join(","));
  if (params?.status) q.set("status", params.status);
  if (params?.category) q.set("category", params.category);
  if (params?.risk_level) q.set("risk_level", params.risk_level);
  if (params?.batch_id) q.set("batch_id", params.batch_id);
  if (params?.since) q.set("since", params.since);
  if (typeof params?.limit === "number") q.set("limit", String(params.limit));
  const suffix = q.toString() ? `?${q.toString()}` : "";
  return apiGet<ResponseActionOut[]>(`/api/response/actions${suffix}`, opts);
}

export function getResponseAction(actionId: number) {
  return apiGet<ResponseActionOut>(`/api/response/actions/${actionId}`);
}

export function getResponseActionResult(actionId: number) {
  return apiGet<ResponseActionResultOut>(`/api/response/actions/${actionId}/result`);
}

export function getResponseActionTimeline(actionId: number) {
  return apiGet<TimelineEventOut[]>(`/api/response/actions/${actionId}/timeline`);
}

export function createResponseAction(payload: ResponseActionCreateIn & { justification?: string }) {
  return apiPost<ResponseActionOut>("/api/response/actions", payload);
}

export function createResponseActionBatch(payload: BatchDispatchIn) {
  return apiPost<BatchDispatchOut>("/api/response/actions/batch", payload);
}

export function cancelResponseAction(actionId: number) {
  return apiPost<ResponseActionOut>(`/api/response/actions/${actionId}/cancel`);
}
