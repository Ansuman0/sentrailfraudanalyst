import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Empty, ErrorBox, Loading, PageHeader } from "../components/common";
import { useAuth } from "../hooks/useAuth";
import { admin } from "../services/sentrail";
import type { AdminUser } from "../types/api";
import { fmtDateTime } from "../utils/format";

export function Users() {
  const { me } = useAuth();
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ["admin-users"], queryFn: admin.users });
  const roles = useQuery({ queryKey: ["admin-roles"], queryFn: admin.roles, retry: false });
  const roleList = roles.data?.roles ?? [];
  const refresh = () => qc.invalidateQueries({ queryKey: ["admin-users"] });

  const [email, setEmail] = useState("");
  const [roleId, setRoleId] = useState("");
  const invite = useMutation({
    mutationFn: () => admin.invite(email.trim(), roleId),
    onSuccess: () => { setEmail(""); refresh(); },
  });
  const update = useMutation({
    mutationFn: (a: { id: string; patch: { role_id?: string; status?: "active" | "suspended" } }) => admin.updateUser(a.id, a.patch),
    onSuccess: refresh,
  });
  const onInvite = (e: FormEvent) => { e.preventDefault(); invite.mutate(); };

  // Sensitive actions need a written reason, which the API records in the audit log.
  const [pending, setPending] = useState<{ kind: "reveal" | "reset"; user: AdminUser } | null>(null);
  const [reason, setReason] = useState("");
  const sensitive = useMutation<{ email?: string; ok?: boolean }, Error, { kind: "reveal" | "reset"; id: string; reason: string }>({
    mutationFn: (a) =>
      a.kind === "reveal" ? admin.revealEmail(a.id, a.reason) : admin.resetMfa(a.id, a.reason),
    onSuccess: (_data, a) => { if (a.kind === "reset") { closeAction(); refresh(); } },
  });
  const closeAction = () => { setPending(null); setReason(""); sensitive.reset(); };
  const open = (kind: "reveal" | "reset", user: AdminUser) => { sensitive.reset(); setReason(""); setPending({ kind, user }); };
  const onSensitive = (e: FormEvent) => {
    e.preventDefault();
    if (pending) sensitive.mutate({ kind: pending.kind, id: pending.user.id, reason: reason.trim() });
  };

  const row = (u: AdminUser) => {
    const self = u.id === me?.user_id;
    const current = roleList.find((r) => r.name === u.role);
    return (
      <tr key={u.id}>
        <td>{u.name ?? "—"}{self && <span className="muted"> (you)</span>}</td>
        <td className="mono">{u.email}</td>
        <td>
          {roleList.length && current && !self ? (
            <select aria-label={`Role for ${u.name ?? u.email}`} value={current.id} disabled={update.isPending}
                    onChange={(e) => update.mutate({ id: u.id, patch: { role_id: e.target.value } })}>
              {roleList.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
          ) : u.role}
        </td>
        <td>{u.status}</td>
        <td>{u.mfa ? "On" : "Off"}</td>
        <td>{fmtDateTime(u.last_login)}</td>
        <td>
          {!self && <button className="btn" onClick={() => open("reveal", u)}>Reveal email</button>}{" "}
          {!self && u.mfa && <button className="btn" onClick={() => open("reset", u)}>Reset two-factor</button>}{" "}
          {!self && u.status === "active" && (
            <button className="btn danger" disabled={update.isPending}
                    onClick={() => update.mutate({ id: u.id, patch: { status: "suspended" } })}>Suspend</button>
          )}
          {!self && u.status === "suspended" && (
            <button className="btn" disabled={update.isPending}
                    onClick={() => update.mutate({ id: u.id, patch: { status: "active" } })}>Reactivate</button>
          )}
        </td>
      </tr>
    );
  };

  return (
    <>
      <PageHeader title="Users" sub="Invite people, change their role, or suspend access. Role and status changes take effect on their next request." />
      <form className="panel narrow" onSubmit={onInvite} aria-label="Invite a user">
        <div className="fields2">
          <div className="field">
            <label htmlFor="inv-email">Work email</label>
            <input id="inv-email" type="email" required autoComplete="off" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="inv-role">Role</label>
            <select id="inv-role" required value={roleId} onChange={(e) => setRoleId(e.target.value)} disabled={!roleList.length}>
              <option value="" disabled>Choose a role</option>
              {roleList.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
            {roles.isError && <small>Your role can't list roles (it needs “manage roles”), so you can't invite from here.</small>}
          </div>
        </div>
        {invite.isError && <ErrorBox error={invite.error} />}
        {invite.isSuccess && (
          <p className="verified">
            Invitation sent to {invite.data.invited}.
            {invite.data.dev_link && <> Development link: <span className="mono">{invite.data.dev_link}</span></>}
          </p>
        )}
        <div className="actions"><button className="btn primary" disabled={invite.isPending || !roleId || !email}>{invite.isPending ? "Sending…" : "Send invitation"}</button></div>
      </form>

      {pending && (
        <form className="panel narrow" onSubmit={onSensitive} aria-label={pending.kind === "reveal" ? "Reveal email" : "Reset two-factor"}>
          <b>{pending.kind === "reveal" ? `Reveal the full email of ${pending.user.name ?? pending.user.email}` : `Reset two-factor for ${pending.user.name ?? pending.user.email}`}</b>
          <p className="muted">
            {pending.kind === "reveal"
              ? "Emails are masked by default. Revealing one is recorded in the audit log with your reason."
              : "They are signed out everywhere and set up two-factor again at their next sign-in. Recorded in the audit log with your reason."}
          </p>
          {sensitive.isSuccess && sensitive.data?.email ? (
            <p role="status">Email: <span className="mono" data-testid="revealed-email">{sensitive.data.email}</span></p>
          ) : (
            <div className="field">
              <label htmlFor="reason">Reason (5–500 characters)</label>
              <textarea id="reason" required minLength={5} maxLength={500} rows={3} value={reason} onChange={(e) => setReason(e.target.value)} />
            </div>
          )}
          {sensitive.isError && <ErrorBox error={sensitive.error} />}
          <div className="actions">
            <button type="button" className="btn" onClick={closeAction}>{sensitive.isSuccess ? "Done" : "Cancel"}</button>
            {!sensitive.isSuccess && <button className="btn primary" disabled={sensitive.isPending || reason.trim().length < 5}>{sensitive.isPending ? "Working…" : pending.kind === "reveal" ? "Reveal" : "Reset two-factor"}</button>}
          </div>
        </form>
      )}
      {update.isError && <ErrorBox error={update.error} title="That change wasn't made" />}
      <h2>People</h2>
      {users.isPending ? <Loading /> : users.isError ? <ErrorBox error={users.error} /> : users.data.length === 0 ? <Empty>No users yet.</Empty> : (
        <div className="tablewrap">
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Two-factor</th><th>Last sign-in</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>{users.data.map(row)}</tbody>
          </table>
        </div>
      )}
    </>
  );
}
