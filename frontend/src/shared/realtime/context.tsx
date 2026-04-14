import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import {
  createPortalRealtimeClient,
  type RealtimeConnectionSnapshot,
  type PortalRealtimeAnyListener,
  type PortalRealtimeClient,
  type PortalRealtimeEventListener,
  type RealtimeConnectionStatus,
} from "@/shared/realtime/client";
import type { PortalRealtimeAnyEvent, PortalRealtimeEventType } from "@/shared/realtime/types";

type PortalRealtimeContextValue = {
  status: RealtimeConnectionStatus;
  connection: RealtimeConnectionSnapshot;
  subscribe: <K extends PortalRealtimeEventType>(
    eventType: K,
    listener: PortalRealtimeEventListener<K>,
  ) => () => void;
  subscribeAll: (listener: PortalRealtimeAnyListener) => () => void;
};

const PortalRealtimeContext = createContext<PortalRealtimeContextValue | null>(null);

export function PortalRealtimeProvider({ children, enabled = true }: { children: ReactNode; enabled?: boolean }) {
  const clientRef = useRef<PortalRealtimeClient | null>(null);
  if (!clientRef.current) {
    clientRef.current = createPortalRealtimeClient();
  }
  const client = clientRef.current;

  const [status, setStatus] = useState<RealtimeConnectionStatus>(client.status);
  const [connection, setConnection] = useState<RealtimeConnectionSnapshot>(client.connection);

  useEffect(() => {
    const unsubscribe = client.subscribeStatus((nextStatus) => {
      setStatus(nextStatus);
    });
    return unsubscribe;
  }, [client]);

  useEffect(() => {
    const unsubscribe = client.subscribeConnection((nextConnection) => {
      setConnection(nextConnection);
    });
    return unsubscribe;
  }, [client]);

  useEffect(() => {
    if (enabled) {
      client.start();
    } else {
      client.stop();
    }
    return () => {
      client.stop();
    };
  }, [client, enabled]);

  const subscribe = useCallback<PortalRealtimeContextValue["subscribe"]>(
    (eventType, listener) => client.subscribe(eventType, listener),
    [client],
  );

  const subscribeAll = useCallback<PortalRealtimeContextValue["subscribeAll"]>(
    (listener) => client.subscribeAll(listener),
    [client],
  );

  const value = useMemo<PortalRealtimeContextValue>(
    () => ({
      status,
      connection,
      subscribe,
      subscribeAll,
    }),
    [connection, status, subscribe, subscribeAll],
  );

  return <PortalRealtimeContext.Provider value={value}>{children}</PortalRealtimeContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function usePortalRealtime(): PortalRealtimeContextValue {
  const context = useContext(PortalRealtimeContext);
  if (!context) {
    throw new Error("usePortalRealtime must be used within PortalRealtimeProvider");
  }
  return context;
}

// eslint-disable-next-line react-refresh/only-export-components
export function usePortalRealtimeSubscription<K extends PortalRealtimeEventType>(
  eventType: K,
  listener: PortalRealtimeEventListener<K> | null | undefined,
): void {
  const { subscribe } = usePortalRealtime();
  const listenerRef = useRef<PortalRealtimeEventListener<K> | null>(listener ?? null);

  useEffect(() => {
    listenerRef.current = listener ?? null;
  }, [listener]);

  useEffect(() => {
    const wrapped: PortalRealtimeEventListener<K> = (event) => {
      listenerRef.current?.(event);
    };
    return subscribe(eventType, wrapped);
  }, [eventType, subscribe]);
}

// eslint-disable-next-line react-refresh/only-export-components
export function usePortalRealtimeAnySubscription(listener: ((event: PortalRealtimeAnyEvent) => void) | null | undefined): void {
  const { subscribeAll } = usePortalRealtime();
  const listenerRef = useRef<((event: PortalRealtimeAnyEvent) => void) | null>(listener ?? null);

  useEffect(() => {
    listenerRef.current = listener ?? null;
  }, [listener]);

  useEffect(() => {
    const wrapped = (event: PortalRealtimeAnyEvent) => {
      listenerRef.current?.(event);
    };
    return subscribeAll(wrapped);
  }, [subscribeAll]);
}
