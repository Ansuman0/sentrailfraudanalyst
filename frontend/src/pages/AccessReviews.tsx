import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Empty, ErrorBox, Loading, PageHeader } from "../components/common";
import { admin, governance } from "../services/sentrail";
import type { ReviewDetail, ReviewMember } from "../types/api";
import { fmtDateTime } from "../utils/format";

type Scope = "tenant" | "platform";

/** One person in a review: keep, change to another role, or remove (suspend). The server refuses what it must (your own row, the last admin). */
function MemberRow({ review, m, scope, roles, onDone }: { review: ReviewDetail; m: ReviewMember; scope: Scope; roles: { id: string; name: string }[]; onDone: () => void }) {
  const api = governance.reviews(scope);
  const [newRole, setNewRole] = useState(m.new_role_id ?? "");
  const decide = useMutation({
    mutationFn: (a: { decision: "keep" | "change" | "remove"; new_role_id?: string }) => api.decide(review.id, m.user_id, a),
    onSuccess: onDone,
  });
  const closed = review.status !== "open";
  return (
    <tr>
      <td>{m.name ?? "—"}</td>
      <td className="mono">{m.email ?? "—"}</td>
      <td>{m.role}</td>
      <td>{m.decision ? <b>{m.decision}</b> : <span className="muted">not decided</span>}</td>
      <td>
        {!closed && (
          <>
            <button className="btn" disabled={decide.isPending} onClick={() => decide.mutate({ decision: "keep" })}>Keep</button>{" "}
            <select aria-label={`New role for ${m.name ?? m.email}`} value={newRole} onChange={(e) => setNewRole(e.target.value)}>
              <option value="">Change to…</option>
              {roles.filter((r) => r.name !== m.role).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>{" "}
            <button className="btn" disabled={decide.isPending || !newRole} onClick={() => decide.mutate({ decision: "change", new_role_id: newRole })}>Change</button>{" "}
            <button className="btn danger" disabled={decide.isPending} onClick={() => decide.mutate({ decision: "remove" })}>Remove</button>
          </>
        )}
        {decide.isError && <ErrorBox error={decide.error} />}
      </td>
    </tr>
  );
}

export function AccessReviews({ scope = "tenant" }: { scope?: Scope }) {
  const qc = useQueryClient();
  const api = governance.reviews(scope);
  const key = ["reviews", scope];
  const list = useQuery({ queryKey: key, queryFn: api.list });
  const [openId, setOpenId] = useState<string | null>(null);
  const detail = useQuery({ queryKey: [...key, openId], queryFn: () => api.get(openId as string), enabled: !!openId });
  const roles = useQuery({ queryKey: ["admin-roles"], queryFn: admin.roles, enabled: scope === "tenant", retry: false });
  const roleList = (roles.data?.roles ?? []).filter((r) => !r.locked);
  const refresh = () => { void qc.invalidateQueries({ queryKey: key }); };

  const start = useMutation({ mutationFn: () => api.open(), onSuccess: (r) => { refresh(); setOpenId(r.id); } });
  const signOff = useMutation({ mutationFn: (id: string) => api.signOff(id), onSuccess: refresh });
  const undecided = detail.data ? detail.data.members.filter((m) => !m.decision).length : 0;

  return (
    <>
      <PageHeader
        title={scope === "tenant" ? "Access reviews" : "Platform staff access review"}
        sub={scope === "tenant"
          ? "Each quarter, mark everyone in your organization keep, change or remove, then sign off. Removing suspends the person and signs them out; nobody is deleted."
          : "Owners review the platform's own staff. Changing or removing an owner needs a second owner's approval, so it isn't done here."}
      >
        <button className="btn primary" disabled={start.isPending} onClick={() => start.mutate()}>{start.isPending ? "Opening…" : "Open a review"}</button>
      </PageHeader>
      {start.isError && <ErrorBox error={start.error} />}
      {list.isPending ? <Loading /> : list.isError ? <ErrorBox error={list.error} /> : list.data.length === 0 ? <Empty>No reviews yet.</Empty> : (
        <div className="tablewrap">
          <table>
            <thead><tr><th>Review</th><th>Opened</th><th>Due</th><th>Progress</th><th>Status</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {list.data.map((r) => (
                <tr key={r.id}>
                  <td>{r.title}</td>
                  <td>{fmtDateTime(r.opened_at)}</td>
                  <td>{fmtDateTime(r.due_at)}{r.overdue && <span className="muted"> · overdue</span>}</td>
                  <td>{r.decided ?? 0} of {r.items ?? 0}</td>
                  <td>{r.status === "signed_off" ? `Signed off ${fmtDateTime(r.signed_off_at)}` : r.status}</td>
                  <td><button className="btn" onClick={() => setOpenId(openId === r.id ? null : r.id)}>{openId === r.id ? "Hide" : "Open"}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {openId && (detail.isPending ? <Loading /> : detail.isError ? <ErrorBox error={detail.error} /> : (
        <>
          <h2>{detail.data.title}</h2>
          <div className="tablewrap">
            <table>
              <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Decision</th><th><span className="sr-only">Decide</span></th></tr></thead>
              <tbody>
                {detail.data.members.map((m) => (
                  <MemberRow key={m.user_id} review={detail.data} m={m} scope={scope} roles={scope === "tenant" ? roleList : []} onDone={refresh} />
                ))}
              </tbody>
            </table>
          </div>
          {detail.data.status === "open" && (
            <div className="actions">
              <button className="btn primary" disabled={signOff.isPending || undecided > 0} onClick={() => signOff.mutate(detail.data.id)}>
                {signOff.isPending ? "Signing off…" : "Sign off and apply decisions"}
              </button>
              {undecided > 0 && <span className="muted"> {undecided} still need a decision</span>}
            </div>
          )}
          {signOff.isError && <ErrorBox error={signOff.error} />}
          {signOff.isSuccess && <p className="verified">Signed off. Kept {signOff.data.keep}, changed {signOff.data.change}, removed {signOff.data.remove}. Recorded in the audit log.</p>}
        </>
      ))}
    </>
  );
}

export const StaffAccessReview = () => <AccessReviews scope="platform" />;
