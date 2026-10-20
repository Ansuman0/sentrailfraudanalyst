import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ErrorBox, Loading, PageHeader } from "../components/common";
import { useAuth } from "../hooks/useAuth";
import { me as meApi } from "../services/sentrail";
import { fmtDateTime } from "../utils/format";

export function Account() {
  const { me } = useAuth();
  const qc = useQueryClient();
  const sessions = useQuery({ queryKey: ["sessions"], queryFn: meApi.sessions });
  const done = () => qc.invalidateQueries({ queryKey: ["sessions"] });
  const end = useMutation({ mutationFn: meApi.endSession, onSuccess: done });
  const endOthers = useMutation({ mutationFn: meApi.endOthers, onSuccess: done });
  if (!me) return null;
  const others = sessions.data?.filter((s) => !s.current).length ?? 0;

  return (
    <>
      <PageHeader title="My account" sub={`${me.role} at ${me.tenant.name}`} />
      <div className="grid g2">
        <section className="panel">
          <h2>Profile</h2>
          <div className="keycard">
            <div><b>{me.name ?? "—"}</b>Name</div>
            <div><b className="mono">{me.email}</b>Email (masked)</div>
            <div><b>{me.role}</b>Role</div>
            <div>
              <b>{me.mfa_enabled ? "On" : "Off"}</b>Two-factor
            </div>
          </div>
          <h2 className="mt">Two-factor authentication</h2>
          {me.mfa_enabled ? (
            <p className="sub">On. Sign-in asks for a code from your authenticator app. Lost your phone? Use a recovery code, or ask an admin to reset it.</p>
          ) : me.mfa_setup === "required" ? (
            <p className="sub">Your organization requires two-factor. <Link to="/setup-2fa?return_to=%2Faccount">Set it up</Link> to continue.</p>
          ) : (
            <>
              <p className="sub">Off. Turning it on is your choice: you scan a QR code with an authenticator app, then sign in with a code as well as your password. It's needed to approve STRs, export cases, change the screening policy and override held screenings.</p>
              <div className="actions"><Link className="btn primary" to="/setup-2fa?return_to=%2Faccount">Turn on two-factor</Link></div>
            </>
          )}
          <h2 className="mt">Permissions</h2>
          <p className="perms">{me.permissions.map((p) => <span key={p} className="ch">{p}</span>)}</p>
        </section>
        <section className="panel">
          <h2>Signed-in devices</h2>
          {sessions.isPending ? <Loading /> : sessions.isError ? <ErrorBox error={sessions.error} /> : sessions.data.map((s) => (
            <div key={s.id} className="sess">
              <span>{s.device || "Unknown device"}{s.current && <span className="rolechip"> This device</span>}</span>
              {!s.current && (
                <button className="linkbtn" disabled={end.isPending} onClick={() => end.mutate(s.id)}>Sign out</button>
              )}
              <small>{s.ip ?? "unknown IP"} · {s.method} · active {fmtDateTime(s.last_active)}</small>
            </div>
          ))}
          {(end.isError || endOthers.isError) && <ErrorBox error={end.error ?? endOthers.error} />}
          {others > 0 && (
            <div className="actions">
              <button className="btn danger" disabled={endOthers.isPending} onClick={() => endOthers.mutate()}>
                Sign out {others} other device{others === 1 ? "" : "s"}
              </button>
            </div>
          )}
        </section>
      </div>
    </>
  );
}
