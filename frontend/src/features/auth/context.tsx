import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import { authApi, refreshSession, setAccessToken } from "@/shared/lib/http";
import type { AuthUser, TokenOut } from "@/shared/lib/http";

export type AuthStatus = "loading" | "anon" | "authed";

export type AuthCtx = {
  status: AuthStatus;
  user: AuthUser | null;
  loginWithPassword: (username: string, password: string) => Promise<void>;
  loginWithOtp: (token: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
};

const AuthContext = createContext<AuthCtx | null>(null);

function normalizeUser(u: any): AuthUser | null {
  if (!u || typeof u !== "object") return null;
  const id = Number((u as any).id);
  const username = String((u as any).username || "").trim();
  const role = String((u as any).role || "").trim();
  if (!Number.isFinite(id) || id <= 0 || !username) return null;
  return { id, username, role };
}

function normalizeTokenOut(x: any): TokenOut | null {
  if (!x || typeof x !== "object") return null;
  const access_token = String((x as any).access_token || "").trim();
  const token_type = String((x as any).token_type || "bearer").toLowerCase() as any;
  const expires_in = Number((x as any).expires_in);
  const user = normalizeUser((x as any).user);
  if (!access_token || token_type !== "bearer" || !Number.isFinite(expires_in) || expires_in <= 0 || !user) return null;
  return { access_token, token_type: "bearer", expires_in, user };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>("loading");
  const [user, setUser] = useState<AuthUser | null>(null);

  const booted = useRef(false);

  const refresh = useCallback(async () => {
    const r = await refreshSession();
    if (r.accessToken && r.user) {
      setUser(r.user);
      setStatus("authed");
      return;
    }
    setUser(null);
    setStatus("anon");
  }, []);

  useEffect(() => {
    if (booted.current) return;
    booted.current = true;
    refresh();
  }, [refresh]);

  const loginWithPassword = useCallback(async (username: string, password: string) => {
    const data = normalizeTokenOut(await authApi.login(username, password));
    if (!data) throw new Error("Login failed");
    setAccessToken(data.access_token);
    setUser(data.user);
    setStatus("authed");
  }, []);

  const loginWithOtp = useCallback(async (token: string) => {
    const data = normalizeTokenOut(await authApi.otpLogin(token));
    if (!data) throw new Error("Login failed");
    setAccessToken(data.access_token);
    setUser(data.user);
    setStatus("authed");
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } finally {
      setAccessToken(null);
      setUser(null);
      setStatus("anon");
    }
  }, []);

  const value = useMemo<AuthCtx>(
    () => ({
      status,
      user,
      loginWithPassword,
      loginWithOtp,
      logout,
      refresh,
    }),
    [status, user, loginWithPassword, loginWithOtp, logout, refresh]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
