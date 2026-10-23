import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { hasAccessToken, onSignedOut, refreshSession, setAccessToken } from "../services/http";
import { auth, governance, me as meApi, tenants as tenantsApi } from "../services/sentrail";
import type { Me } from "../types/api";

type Status = "loading" | "signed_out" | "signed_in";

interface AuthState {
  status: Status;
  me: Me | null;
  /** Store a freshly issued access token and load the signed-in user. */
  completeSignIn: (accessToken: string) => Promise<void>;
  /** Two-factor screen to show now: "required" blocks the app, "offer" right after signing in when it's optional. */
  mfaGate: "required" | null;
  /** "Skip for now" on the optional offer (until the next sign-in). */
  signOut: () => Promise<void>;
  can: (perm: string) => boolean;
  canAny: (...perms: string[]) => boolean;
  hasFeature: (feature: string) => boolean;
  /** Re-read /me (permissions, features) after an admin change. A failure keeps the current session. */
  refreshMe: () => Promise<void>;
  /** Move to another tenant (null = the platform console): a new session, then reload who and where we are. */
  switchTenant: (tenantId: string | null) => Promise<void>;
  /** "Preview as role" (Tenant admins): the app shows only what that role would see. It changes the screens, never the server's decisions. */
  preview: { role: string } | null;
  startPreview: (roleId: string) => Promise<void>;
  stopPreview: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>("loading");
  const [me, setMe] = useState<Me | null>(null);
  const queryClient = useQueryClient();
  const [previewing, setPreviewing] = useState<{ role: string; permissions: string[]; features: string[] } | null>(null);

  const reset = useCallback(() => {
    setAccessToken(null);
    setMe(null);
    setPreviewing(null);
    queryClient.clear(); // never show one user's cached data to the next
    setStatus("signed_out");
  }, [queryClient]);

  const loadMe = useCallback(async () => {
    try {
      setMe(await meApi.get());
      setStatus("signed_in");
    } catch {
      reset();
    }
  }, [reset]);

  // On start (and after an OIDC redirect back from the API), resume the session from the refresh cookie.
  // refreshSession() is single-flight, so React StrictMode running this effect twice is safe.
  useEffect(() => {
    let alive = true;
    (async () => {
      const ok = hasAccessToken() || (await refreshSession());
      if (!alive) return;
      if (ok) await loadMe();
      else setStatus("signed_out");
    })();
    return () => {
      alive = false;
    };
  }, [loadMe]);

  useEffect(() => {
    const off = onSignedOut(reset);
    return () => {
      off();
    };
  }, [reset]);

  const completeSignIn = useCallback(
    async (token: string) => {
      setAccessToken(token);
      try {
        const m = await meApi.get();
        setMe(m);
        setStatus("signed_in");
      } catch {
        reset();
      }
    },
    [reset],
  );

  const signOut = useCallback(async () => {
    try {
      await auth.logout();
    } finally {
      reset();
    }
  }, [reset]);

  const refreshMe = useCallback(async () => {
    try {
      setMe(await meApi.get());
    } catch {
      /* the next request will surface a real sign-out */
    }
  }, []);

  const switchTenant = useCallback(async (tenantId: string | null) => {
    const r = await tenantsApi.switchTo(tenantId);
    setAccessToken(r.access_token);
    queryClient.clear(); // nothing from one tenant may show up in the next
    setPreviewing(null);
    setMe(await meApi.get());
  }, [queryClient]);

  const startPreview = useCallback(async (roleId: string) => {
    const e = await governance.effectiveForRole(roleId);
    setPreviewing({ role: e.role, permissions: e.permissions.map((p) => p.key), features: e.features });
  }, []);
  const stopPreview = useCallback(() => setPreviewing(null), []);

  const value = useMemo<AuthState>(() => {
    const perms = new Set(previewing ? previewing.permissions : (me?.permissions ?? []));
    const features = new Set(previewing ? previewing.features : (me?.features ?? []));
    const mfaGate = me?.mfa_setup === "required" ? "required" : null;
    return {
      status, me, completeSignIn, signOut, mfaGate,
      can: (p) => perms.has(p),
      canAny: (...ps) => ps.some((p) => perms.has(p)),
      hasFeature: (f) => features.has(f),
      refreshMe, switchTenant,
      preview: previewing ? { role: previewing.role } : null, startPreview, stopPreview,
    };
  }, [status, me, completeSignIn, signOut, refreshMe, switchTenant, previewing, startPreview, stopPreview]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
