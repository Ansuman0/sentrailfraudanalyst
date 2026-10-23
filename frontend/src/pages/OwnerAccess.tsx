import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Empty, ErrorBox, Loading, PageHeader } from "../components/common";
import { ownerAccess } from "../services/sentrail";
import type { AccessRequest } from "../types/api";
import { fmtDateTime } from "../utils/format";

/** The organization's side of platform owner access: approve or deny requests, and cut a live session short. Every row is also in the audit log. */
export function OwnerAccess() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["owner-requests"], queryFn: ownerAccess.requests });
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["owner-requests"] }); };
  const [denying, setDenying] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const approve = useMutation({ mutationFn: (id: string) => ownerAccess.approve(id), onSuccess: refresh });
  const deny = useMutation({ mutationFn: (a: { id: string; reason: string }) => ownerAccess.deny(a.id, a.reason), onSuccess: () => { setDenying(null); setReason(""); refresh(); } });
  const end = useMutation({ mutationFn: (id: string) => ownerAccess.endForTenant(id), onSuccess: refresh });

  const actions = (r: AccessRequest) => {
    if (r.status === "requested") {
      return denying === r.id ? (
        <form onSubmit={(e) => { e.preventDefault(); deny.mutate({ id: r.id, reason: reason.trim() }); }} aria-label="Deny this request">
          <input aria-label="Reason for denying" required minLength={5} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (5+ characters)" />{" "}
          <button className="btn danger" disabled={deny.isPending || reason.trim().length < 5}>Deny</button>{" "}
          <button type="button" className="btn" onClick={() => setDenying(null)}>Cancel</button>
        </form>
      ) : (
        <>
          <button className="btn primary" disabled={approve.isPending} onClick={() => approve.mutate(r.id)}>Approve</button>{" "}
          <button className="btn" onClick={() => { setDenying(r.id); setReason(""); }}>Deny</button>
        </>
      );
    }
    if (r.status === "active") return <button className="btn danger" disabled={end.isPending} onClick={() => end.mutate(r.id)}>End access now</button>;
    return null;
  };

  return (
    <>
      <PageHeader title="Platform access requests" sub="Sentrail's platform owners can enter your organization only through a time-limited session. Depending on your setting under Security, you approve each request, or they start at once, or they are refused. Everything they do is in your audit log." />
      {(approve.isError || deny.isError || end.isError) && <ErrorBox error={approve.error ?? deny.error ?? end.error} />}
      {q.isPending ? <Loading /> : q.isError ? <ErrorBox error={q.error} /> : q.data.length === 0 ? <Empty>No owner has asked to enter your organization.</Empty> : (
        <div className="tablewrap">
          <table>
            <thead><tr><th>Requested</th><th>Reason given</th><th>Status</th><th>Until</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {q.data.map((r) => (
                <tr key={r.id}>
                  <td>{fmtDateTime(r.requested_at)}</td>
                  <td>{r.reason}{r.legal_hold && <span className="muted"> · legal hold</span>}</td>
                  <td>{r.status}{r.ended_reason ? ` (${r.ended_reason})` : ""}</td>
                  <td>{r.expires_at ? fmtDateTime(r.expires_at) : r.request_expires_at && r.status === "requested" ? `decide by ${fmtDateTime(r.request_expires_at)}` : "—"}</td>
                  <td>{actions(r)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
