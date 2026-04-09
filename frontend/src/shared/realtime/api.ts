import { apiPost } from "@/shared/lib/http";

export type StreamTokenOut = {
  stream_token: string;
  token_type: "stream";
  expires_in: number;
};

export function requestRealtimeStreamToken(): Promise<StreamTokenOut> {
  return apiPost<StreamTokenOut>("/api/realtime/token");
}
