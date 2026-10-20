import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";
import { Loading } from "./common";

export function RequireAuth({ children }: { children: ReactNode }) {
  const { status, mfaGate } = useAuth();
  const location = useLocation();
  const back = location.pathname + location.search;
  if (status === "loading") return <div className="center"><Loading label="Checking your session…" /></div>;
  if (status === "signed_out") return <Navigate to={`/signin?return_to=${encodeURIComponent(back)}`} replace />;
  if (mfaGate && location.pathname !== "/setup-2fa") {
    return <Navigate to={`/setup-2fa?return_to=${encodeURIComponent(back)}`} replace />;
  }
  return <>{children}</>;
}

/** Shown in place of a page the role can't use (the API would answer 403 anyway). */
export function RequirePerm({ allowed, children }: { allowed: boolean; children: ReactNode }) {
  if (!allowed) {
    return (
      <>
        <h1>No access</h1>
        <p className="sub">Your role doesn't include this screen. Ask your organization admin if you need it.</p>
      </>
    );
  }
  return <>{children}</>;
}
