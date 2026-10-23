import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Empty, ErrorBox, Loading, PageHeader } from "../components/common";
import { useAuth } from "../hooks/useAuth";
import { ownerAccess, platform, tenantAdmin } from "../services/sentrail";
import type { Organization } from "../types/api";

const PLANS = ["starter", "professional", "enterprise"]; // the API accepts exactly these

type Ask = { org: Organization; kind: "suspended" | "active" | "delete" | "access" };

const ASK_TEXT: Record<Ask["kind"], { title: (o: Organization) => string; help: string; button: string }> = {
  suspended: { title: (o) => `Suspend ${o.legal_name}`, help: "Everyone is signed out and API keys stop working. The data is kept.", button: "Suspend organization" },
  active: { title: (o) => `Reactivate ${o.legal_name}`, help: "People can sign in again.", button: "Reactivate organization" },
  delete: { title: (o) => `Delete ${o.legal_name}`, help: "A second owner has to approve within 24 hours. The data is kept until its retention period ends, then removed.", button: "Ask for deletion" },
  access: { title: (o) => `Enter ${o.legal_name}`, help: "You can only enter through a time-limited session. The organization's setting decides whether it starts at once or waits for their administrator. Everything you do is recorded in their audit log.", button: "Request access" },
};

export function Organizations() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["orgs"], queryFn: platform.orgs });
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["orgs"] }); };
  const [pending, setPending] = useState<{ org: Organization; plan: string } | null>(null);
  const move = useMutation({
    mutationFn: (a: { id: string; plan: string }) => platform.setOrgPlan(a.id, a.plan),
    onSuccess: () => { setPending(null); refresh(); },
  });
  const canMove = can("platform.tenants.manage");

  // suspend / reactivate / delete / enter: all need a written reason, which is recorded
  const [ask, setAsk] = useState<Ask | null>(null);
  const [reason, setReason] = useState("");
  const act = useMutation({
    mutationFn: async (a: Ask) => {
      const r = reason.trim();
      if (a.kind === "delete") return { note: "A second owner has to approve the deletion under Approvals.", ...(await tenantAdmin.requestDelete(a.org.id, r)) };
      if (a.kind === "access") {
        const x = await ownerAccess.request(a.org.id, r);
        return { note: x.status === "active" ? "The session started." : "Waiting for the organization's administrator to approve.", ...x };
      }
      return { note: "Done.", ...(await tenantAdmin.setStatus(a.org.id, a.kind, r)) };
    },
    onSuccess: () => { refresh(); },
  });
  const close = () => { setAsk(null); setReason(""); act.reset(); };
  const onAct = (e: FormEvent) => { e.preventDefault(); if (ask) act.mutate(ask); };

  const [form, setForm] = useState({ legal_name: "", business_type: "MSB", registration: "", admin_email: "", plan: "professional" });
  const create = useMutation({ mutationFn: () => tenantAdmin.create(form), onSuccess: () => { setForm({ ...form, legal_name: "", registration: "", admin_email: "" }); refresh(); } });
  const onCreate = (e: FormEvent) => { e.preventDefault(); create.mutate(); };
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setForm({ ...form, [k]: e.target.value });

  return (
    <>
      <PageHeader title="Organizations" sub="Each organization's data is isolated at the database level. Platform staff manage organizations but can't see their customers or cases." />
      {canMove && (
        <form className="panel narrow" onSubmit={onCreate} aria-label="Create an organization">
          <b>New organization</b>
          <div className="fields2">
            <div className="field"><label htmlFor="o-name">Legal name</label><input id="o-name" required minLength={2} value={form.legal_name} onChange={set("legal_name")} /></div>
            <div className="field"><label htmlFor="o-reg">Registration number</label><input id="o-reg" required minLength={3} value={form.registration} onChange={set("registration")} /></div>
            <div className="field"><label htmlFor="o-admin">First administrator's email</label><input id="o-admin" type="email" required value={form.admin_email} onChange={set("admin_email")} /></div>
            <div className="field">
              <label htmlFor="o-plan">Plan</label>
              <select id="o-plan" value={form.plan} onChange={set("plan")}>{PLANS.map((p) => <option key={p} value={p}>{p}</option>)}</select>
            </div>
          </div>
          <p className="muted">It starts pending and goes live when the administrator accepts the 72-hour invitation and sets up two-factor.</p>
          {create.isError && <ErrorBox error={create.error} />}
          {create.isSuccess && <p className="verified" role="status">Organization created, invitation sent.{create.data.dev_link && <> Development link: <span className="mono">{create.data.dev_link}</span></>}</p>}
          <div className="actions"><button className="btn primary" disabled={create.isPending}>Create organization</button></div>
        </form>
      )}
      {ask && (
        <form className="alertbox" onSubmit={onAct} aria-label={ASK_TEXT[ask.kind].title(ask.org)}>
          <b>{ASK_TEXT[ask.kind].title(ask.org)}</b> {ASK_TEXT[ask.kind].help}
          {act.isSuccess ? <p role="status">{act.data.note}</p> : (
            <div className="field">
              <label htmlFor="why">Reason (5–500 characters)</label>
              <textarea id="why" required minLength={5} maxLength={500} rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />
            </div>
          )}
          {act.isError && <ErrorBox error={act.error} />}
          <div className="actions">
            <button type="button" className="btn" onClick={close}>{act.isSuccess ? "Done" : "Cancel"}</button>
            {!act.isSuccess && <button className="btn primary" disabled={act.isPending || reason.trim().length < 5}>{act.isPending ? "Working…" : ASK_TEXT[ask.kind].button}</button>}
          </div>
        </form>
      )}
      {pending && (
        <div className="alertbox" role="alert" aria-label="Confirm plan change">
          <b>Move {pending.org.legal_name} from {pending.org.plan} to {pending.plan}?</b> Features the new plan doesn't include switch off at once;
          features it adds switch on, except any the organization turned off itself.
          <div className="actions">
            <button className="btn" onClick={() => { setPending(null); move.reset(); }}>Cancel</button>
            <button className="btn primary" disabled={move.isPending} onClick={() => move.mutate({ id: pending.org.id, plan: pending.plan })}>{move.isPending ? "Moving…" : "Move organization"}</button>
          </div>
          {move.isError && <ErrorBox error={move.error} />}
        </div>
      )}
      {q.isPending ? <Loading /> : q.isError ? <ErrorBox error={q.error} /> : q.data.length === 0 ? <Empty>No organizations yet.</Empty> : (
        <div className="tablewrap">
          <table>
            <thead><tr><th>Organization</th><th>Type</th><th>Registration</th><th>Region</th><th>Plan</th><th>Status</th><th>Users</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {q.data.map((o) => (
                <tr key={o.id}>
                  <td>{o.legal_name}</td><td>{o.business_type}</td><td className="mono">{o.registration}</td>
                  <td>{o.data_region}</td>
                  <td>
                    {canMove ? (
                      <select aria-label={`Plan for ${o.legal_name}`} value={o.plan}
                              onChange={(e) => { move.reset(); setPending({ org: o, plan: e.target.value }); }}>
                        {[...new Set([...PLANS, o.plan])].map((p) => <option key={p} value={p}>{p}</option>)}
                      </select>
                    ) : <span className="planchip">{o.plan}</span>}
                  </td>
                  <td>{o.status}</td><td>{o.users}</td>
                  <td>
                    {canMove && o.status === "active" && <button className="btn" onClick={() => { act.reset(); setReason(""); setAsk({ org: o, kind: "suspended" }); }}>Suspend</button>}
                    {canMove && o.status === "suspended" && <button className="btn" onClick={() => { act.reset(); setReason(""); setAsk({ org: o, kind: "active" }); }}>Reactivate</button>}{" "}
                    {can("platform.tenants.delete") && o.status !== "deleted" && <button className="btn danger" onClick={() => { act.reset(); setReason(""); setAsk({ org: o, kind: "delete" }); }}>Delete…</button>}{" "}
                    {can("platform.tenant.access") && o.status === "active" && <button className="btn" onClick={() => { act.reset(); setReason(""); setAsk({ org: o, kind: "access" }); }}>Request access</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted">{can("platform.tenant.access") && "Once a request is approved (or started), enter the organization from Tenant access sessions."}</p>
    </>
  );
}
