import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Empty, ErrorBox, Loading, PageHeader } from "../components/common";
import { useAuth } from "../hooks/useAuth";
import { approvals, ownerAccess, staff } from "../services/sentrail";
import { fmtDateTime, humanize } from "../utils/format";

/** The platform's own people: invite, change role, suspend. Changes to owners wait for a second owner (see Approvals). */
export function Staff() {
  const { me } = useAuth();
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ["staff"], queryFn: staff.users });
  const roles = useQuery({ queryKey: ["staff-roles"], queryFn: staff.roles, retry: false });
  const roleList = roles.data?.roles ?? [];
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["staff"] }); void qc.invalidateQueries({ queryKey: ["approvals"] }); };
  const [email, setEmail] = useState("");
  const [roleId, setRoleId] = useState("");
  const invite = useMutation({ mutationFn: () => staff.invite(email.trim(), roleId), onSuccess: () => { setEmail(""); refresh(); } });
  const update = useMutation({ mutationFn: (a: { id: string; patch: { role_id?: string; status?: "active" | "suspended" } }) => staff.update(a.id, a.patch), onSuccess: refresh });
  const onInvite = (e: FormEvent) => { e.preventDefault(); invite.mutate(); };
  return (
    <>
      <PageHeader title="Platform staff" sub="The people who run Sentrail. Adding, changing or suspending an owner needs a second owner's approval." />
      <form className="panel narrow" onSubmit={onInvite} aria-label="Invite platform staff">
        <div className="fields2">
          <div className="field">
            <label htmlFor="staff-email">Work email</label>
            <input id="staff-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="staff-role">Role</label>
            <select id="staff-role" required value={roleId} onChange={(e) => setRoleId(e.target.value)} disabled={!roleList.length}>
              <option value="" disabled>Choose a role</option>
              {roleList.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
          </div>
        </div>
        {invite.isError && <ErrorBox error={invite.error} />}
        {invite.isSuccess && <p className="verified">{invite.data.invited ? `Invitation sent to ${invite.data.invited}.` : "Requested: a second owner has to approve it."}</p>}
        <div className="actions"><button className="btn primary" disabled={invite.isPending || !roleId || !email}>Send invitation</button></div>
      </form>
      {update.isError && <ErrorBox error={update.error} title="That change wasn't made" />}
      {update.isSuccess && update.data?.approval_id && <p className="verified" role="status">A second owner has to approve this under Approvals.</p>}
      {users.isPending ? <Loading /> : users.isError ? <ErrorBox error={users.error} /> : users.data.length === 0 ? <Empty>No staff yet.</Empty> : (
        <div className="tablewrap">
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Sign-in</th><th>Last sign-in</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {users.data.map((u) => {
                const self = u.email && me?.email === u.email;
                const current = roleList.find((r) => r.name === u.role);
                return (
                  <tr key={u.id}>
                    <td>{u.name ?? "—"}</td><td className="mono">{u.email}</td>
                    <td>
                      {current && !self ? (
                        <select aria-label={`Role for ${u.name ?? u.email}`} value={current.id} disabled={update.isPending}
                                onChange={(e) => update.mutate({ id: u.id, patch: { role_id: e.target.value } })}>
                          {roleList.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
                        </select>
                      ) : u.role}
                    </td>
                    <td>{u.status}</td><td>{u.sign_in}</td><td>{fmtDateTime(u.last_login)}</td>
                    <td>
                      {!self && u.status === "active" && <button className="btn danger" disabled={update.isPending} onClick={() => update.mutate({ id: u.id, patch: { status: "suspended" } })}>Suspend</button>}
                      {!self && u.status === "suspended" && <button className="btn" disabled={update.isPending} onClick={() => update.mutate({ id: u.id, patch: { status: "active" } })}>Reactivate</button>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

const ACTIONS: Record<string, string> = {
  "tenant.delete": "Delete an organization",
  "tenant.legal_hold": "Legal hold on an organization",
  "owner.add": "Add a platform owner",
  "owner.change": "Change or suspend a platform owner",
  "baseline.loosen": "Loosen the security baseline",
};

/** Second-owner approvals: the requester can never approve their own request. */
export function Approvals() {
  const { me } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["approvals"], queryFn: approvals.list });
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["approvals"] }); };
  const [denying, setDenying] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const approve = useMutation({ mutationFn: (id: string) => approvals.approve(id), onSuccess: refresh });
  const deny = useMutation({ mutationFn: (a: { id: string; reason: string }) => approvals.deny(a.id, a.reason), onSuccess: () => { setDenying(null); setReason(""); refresh(); } });
  const summary = (p: Record<string, unknown>) =>
    Object.entries(p).filter(([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean").map(([k, v]) => `${humanize(k)}: ${String(v)}`).join(" · ");
  return (
    <>
      <PageHeader title="Approvals" sub="High-risk platform actions wait here for a second owner. Nothing is applied until you approve, and requests lapse after 24 hours." />
      {(approve.isError || deny.isError) && <ErrorBox error={approve.error ?? deny.error} />}
      {q.isPending ? <Loading /> : q.isError ? <ErrorBox error={q.error} /> : q.data.length === 0 ? <Empty>Nothing is waiting.</Empty> : (
        <div className="tablewrap">
          <table>
            <thead><tr><th>Requested</th><th>Action</th><th>Details</th><th>Reason</th><th>Status</th><th><span className="sr-only">Decide</span></th></tr></thead>
            <tbody>
              {q.data.map((a) => (
                <tr key={a.id}>
                  <td>{fmtDateTime(a.created_at)}</td>
                  <td>{ACTIONS[a.action] ?? humanize(a.action)}</td>
                  <td className="muted">{summary(a.payload)}</td>
                  <td>{a.reason ?? "—"}</td>
                  <td>{a.status}</td>
                  <td>
                    {a.status === "pending" && a.requested_by !== me?.user_id && (denying === a.id ? (
                      <form aria-label="Deny this request" onSubmit={(e) => { e.preventDefault(); deny.mutate({ id: a.id, reason: reason.trim() }); }}>
                        <input aria-label="Reason for denying" required minLength={5} value={reason} onChange={(e) => setReason(e.target.value)} />{" "}
                        <button className="btn danger" disabled={reason.trim().length < 5 || deny.isPending}>Deny</button>
                      </form>
                    ) : (
                      <>
                        <button className="btn primary" disabled={approve.isPending} onClick={() => approve.mutate(a.id)}>Approve</button>{" "}
                        <button className="btn" onClick={() => { setDenying(a.id); setReason(""); }}>Deny</button>
                      </>
                    ))}
                    {a.status === "pending" && a.requested_by === me?.user_id && <span className="muted">Waiting for a second owner</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

/** Every owner access session across tenants. Owners can extend (once) or end their own; auditors can only read. */
export function AccessSessions() {
  const { can, me, switchTenant } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["access-sessions"], queryFn: ownerAccess.sessions });
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["access-sessions"] }); };
  const extend = useMutation({ mutationFn: (id: string) => ownerAccess.extend(id), onSuccess: refresh });
  const end = useMutation({ mutationFn: (id: string) => ownerAccess.end(id), onSuccess: refresh });
  const mine = (ownerId: string) => ownerId === me?.user_id;
  return (
    <>
      <PageHeader title="Tenant access sessions" sub="Who entered which organization, why, and until when. Each session lasts 60 minutes with one extension. All of it is in the organization's audit log too." />
      {(extend.isError || end.isError) && <ErrorBox error={extend.error ?? end.error} />}
      {q.isPending ? <Loading /> : q.isError ? <ErrorBox error={q.error} /> : q.data.length === 0 ? <Empty>No sessions yet.</Empty> : (
        <div className="tablewrap">
          <table>
            <thead><tr><th>Organization</th><th>Reason</th><th>Status</th><th>Until</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {q.data.map((s) => (
                <tr key={s.id}>
                  <td>{s.tenant}</td>
                  <td>{s.reason}{s.legal_hold && <span className="muted"> · legal hold</span>}</td>
                  <td>{s.status}{mine(s.owner_user_id) ? " (yours)" : ""}</td>
                  <td>{fmtDateTime(s.expires_at)}</td>
                  <td>
                    {can("platform.tenant.access") && s.status === "active" && mine(s.owner_user_id) && (
                      <>
                        <button className="btn primary" onClick={() => void switchTenant(s.tenant_id)}>Enter</button>{" "}
                        {!s.extended && <button className="btn" disabled={extend.isPending} onClick={() => extend.mutate(s.id)}>Extend 60 min</button>}{" "}
                      </>
                    )}
                    {can("platform.tenant.access") && s.status === "active" && <button className="btn danger" disabled={end.isPending} onClick={() => end.mutate(s.id)}>End</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
