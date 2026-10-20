import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ErrorBox, Loading, PageHeader } from "../components/common";
import { useAuth } from "../hooks/useAuth";
import { platform } from "../services/sentrail";
import type { Plan } from "../types/api";
import { FEATURES, featureInfo } from "../utils/features";

function PlanCard({ plan, editable }: { plan: Plan; editable: boolean }) {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<string[]>(plan.features);
  const [confirming, setConfirming] = useState(false);
  const removed = plan.features.filter((f) => !selected.includes(f));
  const changed = removed.length > 0 || selected.some((f) => !plan.features.includes(f));
  const save = useMutation({
    mutationFn: () => platform.setPlanFeatures(plan.key, selected),
    onSuccess: () => { setConfirming(false); qc.invalidateQueries({ queryKey: ["plans"] }); },
  });
  const toggle = (id: string, on: boolean) => { setConfirming(false); setSelected(on ? [...selected, id] : selected.filter((x) => x !== id)); };
  const ids = [...FEATURES.map((f) => f.id), ...plan.features.filter((f) => !FEATURES.some((k) => k.id === f))];

  return (
    <section className="panel narrow" aria-label={`Plan ${plan.name}`}>
      <h2>{plan.name}</h2>
      <p className="muted">
        {plan.organizations} {plan.organizations === 1 ? "organization" : "organizations"}
        {plan.max_users != null && <> · up to {plan.max_users} users</>}
      </p>
      <fieldset disabled={!editable || save.isPending}>
        <legend className="sr-only">Features in {plan.name}</legend>
        {ids.map((id) => (
          <label key={id} className="toggle">
            <input type="checkbox" checked={selected.includes(id)} onChange={(e) => toggle(id, e.target.checked)} />
            <span><b>{featureInfo(id).name}</b></span>
          </label>
        ))}
      </fieldset>
      {save.isError && <ErrorBox error={save.error} />}
      {editable && changed && !confirming && (
        <div className="actions"><button className="btn primary" onClick={() => setConfirming(true)}>Review change</button></div>
      )}
      {editable && changed && confirming && (
        <div role="alert" className="alertbox">
          <b>This changes {plan.organizations} {plan.organizations === 1 ? "organization" : "organizations"} immediately.</b>
          {removed.length > 0 && <> {removed.map((f) => featureInfo(f).name).join(", ")} will switch off for everyone on this plan, and they must turn it back on themselves if you add it again.</>}
          <div className="actions">
            <button className="btn" onClick={() => setConfirming(false)}>Cancel</button>
            <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Apply to all"}</button>
          </div>
        </div>
      )}
      {save.isSuccess && !changed && <p className="verified">Saved. The change is in the audit log.</p>}
    </section>
  );
}

export function Plans() {
  const { can } = useAuth();
  const q = useQuery({ queryKey: ["plans"], queryFn: platform.plans });
  return (
    <>
      <PageHeader title="Plans" sub="Which features each plan includes. A change applies to every organization on the plan at once." />
      {!can("platform.plans.manage") && <p className="muted">Your role can view plans but not change them.</p>}
      {q.isPending ? <Loading /> : q.isError ? <ErrorBox error={q.error} /> :
        q.data.map((p) => <PlanCard key={`${p.key}-${p.features.join()}`} plan={p} editable={can("platform.plans.manage")} />)}
    </>
  );
}
