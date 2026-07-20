export type LiveRefreshProfileName =
  | "operational"
  | "hot-operational"
  | "expensive-operational"
  | "push-driven"
  | "admin"
  | "background-detail";

export type LiveRefreshCadenceProfile = {
  name: LiveRefreshProfileName;
  label: string;
  reconcileMs: number;
  fallbackMs: number;
  hiddenMs: number | null;
  minGapMs: number;
  invalidateDebounceMs: number;
  reconnectDebounceMs: number;
  immediateRefreshOnReconnect: boolean;
  immediateRefreshOnVisible: boolean;
};

export const LIVE_REFRESH_POLICY = {
  defaultProfile: "operational",
  profiles: {
    operational: {
      name: "operational",
      label: "Operational",
      reconcileMs: 30_000,
      fallbackMs: 10_000,
      hiddenMs: 60_000,
      minGapMs: 2_500,
      invalidateDebounceMs: 300,
      reconnectDebounceMs: 500,
      immediateRefreshOnReconnect: true,
      immediateRefreshOnVisible: true,
    },
    "hot-operational": {
      name: "hot-operational",
      label: "Hot operational",
      reconcileMs: 20_000,
      fallbackMs: 5_000,
      hiddenMs: 30_000,
      minGapMs: 2_000,
      invalidateDebounceMs: 220,
      reconnectDebounceMs: 350,
      immediateRefreshOnReconnect: true,
      immediateRefreshOnVisible: true,
    },
    "expensive-operational": {
      name: "expensive-operational",
      label: "Expensive operational",
      reconcileMs: 60_000,
      fallbackMs: 20_000,
      hiddenMs: 120_000,
      minGapMs: 5_000,
      invalidateDebounceMs: 500,
      reconnectDebounceMs: 900,
      immediateRefreshOnReconnect: true,
      immediateRefreshOnVisible: true,
    },
    "push-driven": {
      name: "push-driven",
      label: "Push driven",
      reconcileMs: 180_000,
      fallbackMs: 15_000,
      hiddenMs: 300_000,
      minGapMs: 5_000,
      invalidateDebounceMs: 400,
      reconnectDebounceMs: 800,
      immediateRefreshOnReconnect: true,
      immediateRefreshOnVisible: true,
    },
    admin: {
      name: "admin",
      label: "Admin",
      reconcileMs: 45_000,
      fallbackMs: 15_000,
      hiddenMs: 90_000,
      minGapMs: 4_000,
      invalidateDebounceMs: 400,
      reconnectDebounceMs: 700,
      immediateRefreshOnReconnect: true,
      immediateRefreshOnVisible: true,
    },
    "background-detail": {
      name: "background-detail",
      label: "Background detail",
      reconcileMs: 90_000,
      fallbackMs: 30_000,
      hiddenMs: null,
      minGapMs: 8_000,
      invalidateDebounceMs: 700,
      reconnectDebounceMs: 1_200,
      immediateRefreshOnReconnect: false,
      immediateRefreshOnVisible: true,
    },
  } satisfies Record<LiveRefreshProfileName, LiveRefreshCadenceProfile>,
} as const;

export const DEFAULT_LIVE_REFRESH_PROFILE = LIVE_REFRESH_POLICY.defaultProfile;

export function resolveLiveRefreshProfile(profile?: LiveRefreshProfileName | LiveRefreshCadenceProfile): LiveRefreshCadenceProfile {
  if (!profile) {
    return LIVE_REFRESH_POLICY.profiles[DEFAULT_LIVE_REFRESH_PROFILE];
  }
  if (typeof profile === "string") {
    return LIVE_REFRESH_POLICY.profiles[profile] ?? LIVE_REFRESH_POLICY.profiles[DEFAULT_LIVE_REFRESH_PROFILE];
  }
  return profile;
}
