import { useEffect, useRef } from "react";

import { usePortalRealtimeSubscription } from "@/shared/realtime";

import { createTopologyInvalidationScheduler, type TopologyInvalidationScheduler } from "../lib/realtime/realtime";

export function useNetworkTopologyRealtimeInvalidation(onInvalidate: () => void) {
  const schedulerRef = useRef<TopologyInvalidationScheduler | null>(null);
  if (!schedulerRef.current) {
    schedulerRef.current = createTopologyInvalidationScheduler(onInvalidate);
  }

  useEffect(() => {
    schedulerRef.current?.setCallback(onInvalidate);
  }, [onInvalidate]);

  useEffect(() => () => schedulerRef.current?.cancel(), []);

  usePortalRealtimeSubscription("ui.network_topology.invalidate", () => {
    schedulerRef.current?.notify();
  });
}
