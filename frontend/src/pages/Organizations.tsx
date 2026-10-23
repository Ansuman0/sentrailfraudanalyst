import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Empty, ErrorBox, Loading, PageHeader } from "../components/common";
import { useAuth } from "../hooks/useAuth";
import { platform } from "../services/sentrail";
import type { Organization } from "../types/api";

const PLANS = ["starter", "professional", "enterprise"]; // the API accepts exactly these

export function Organizations() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["orgs"], queryFn: platform.orgs });
  const [pending, setPending] = useState<{ org: Organization; plan: string } | null>(null);
  const move = useMutation({
    mutationFn: (a: { id: string; plan: string }) => platform.setOrgPlan(a.id, a.plan),
    onSuccess: () => { setPending(null); qc.invalidateQueries({ queryKey: ["orgs"] }); },
  });
  const canMove = can("platform.tenants.manage");

  return (
    <>
      <PageHeader title="Organizations" sub="Each organization's data is isolated at the database level. Platform staff manage organizations but can't see their customers or cases." />
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
            <thead><tr><th>Organization</th><th>Type</th><th>Registration</th><th>Region</th><th>Plan</th><th>Status</th><th>Users</th></tr></thead>
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
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
