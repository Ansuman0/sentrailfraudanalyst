import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Logo } from "../components/Logo";
import { useAuth } from "../hooks/useAuth";

/** Where a sign-in with several memberships lands, and the destination of "Switch tenant". */
export function ChooseTenant() {
  const { me, switchTenant, signOut } = useAuth();
  const navigate = useNavigate();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const choices = me?.tenants ?? [];

  async function pick(id: string | null) {
    setBusy(id ?? "platform");
    setError(null);
    try {
      await switchTenant(id);
      navigate("/", { replace: true });
    } catch {
      setError("You can't enter that organization right now. Try again, or ask your administrator.");
      setBusy(null);
    }
  }

  return (
    <div className="login">
      <div className="card">
        <div className="logo"><Logo size={36} /></div>
        <h1>Choose where to work</h1>
        <p className="lsub">You belong to more than one organization. Each opens as its own session.</p>
        {error && <div className="err" role="alert">{error}</div>}
        <ul className="tenantlist">
          {choices.map((t) => (
            <li key={t.id ?? "platform"}>
              <button type="button" className="btn full" disabled={busy !== null} onClick={() => void pick(t.id)}>
                <strong>{t.name}</strong>
                <span className="muted"> · {t.role}{t.current ? " · current" : ""}</span>
              </button>
            </li>
          ))}
        </ul>
        <button type="button" className="linkbtn" onClick={() => void signOut()}>Sign out</button>
      </div>
    </div>
  );
}

/** Signed in, but with no membership and no platform role. */
export function NoAccess() {
  const { signOut } = useAuth();
  return (
    <div className="login">
      <div className="card">
        <div className="logo"><Logo size={36} /></div>
        <h1>No access yet</h1>
        <p className="lsub">Your account isn't a member of any organization. Ask your administrator to invite you, then sign in again.</p>
        <button type="button" className="btn primary full" onClick={() => void signOut()}>Sign out</button>
      </div>
    </div>
  );
}
