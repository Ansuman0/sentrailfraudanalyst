import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ErrorBox, Loading, PageHeader } from "../components/common";
import { useAuth } from "../hooks/useAuth";
import { govern } from "../services/sentrail";
import type { Policy as PolicyT } from "../types/api";

export function Policy() {
  const { can, me } = useAuth();
  const editable = can("policy.edit") && !!me?.session_mfa;
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["policy"], queryFn: govern.policy });
  const [form, setForm] = useState<PolicyT | null>(null);
  useEffect(() => { if (q.data) setForm(q.data); }, [q.data]);
  const save = useMutation({
    mutationFn: (p: PolicyT) => govern.setPolicy(p),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy"] }),
  });

  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} title="The policy couldn't be loaded" />;
  if (!form) return null;
  const invalid = form.block_at <= form.hold_at;
  const num = (k: keyof PolicyT) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: Number(e.target.value) });
  const onSubmit = (e: FormEvent) => { e.preventDefault(); save.mutate(form); };

  return (
    <>
      <PageHeader title="Screening policy" sub="When crypto transfers are released, held for an analyst, or blocked. Thresholds are in your reporting currency." />
      <form className="panel narrow" onSubmit={onSubmit}>
        <fieldset disabled={!editable || save.isPending}>
          <div className="slider">
            <label htmlFor="hold">Hold for review at score</label><output htmlFor="hold">{form.hold_at}</output>
            <input id="hold" type="range" min={1} max={99} value={form.hold_at} onChange={num("hold_at")} />
          </div>
          <div className="slider">
            <label htmlFor="block">Block at score</label><output htmlFor="block">{form.block_at}</output>
            <input id="block" type="range" min={2} max={100} value={form.block_at} onChange={num("block_at")} />
          </div>
          <div className="fields2">
            <div className="field">
              <label htmlFor="travel">Travel rule threshold</label>
              <input id="travel" type="number" min={0} value={form.travel_rule_threshold} onChange={num("travel_rule_threshold")} />
            </div>
            <div className="field">
              <label htmlFor="proof">Self-hosted wallet proof above</label>
              <input id="proof" type="number" min={0} value={form.self_hosted_proof_above} onChange={num("self_hosted_proof_above")} />
            </div>
          </div>
          <label className="toggle">
            <input type="checkbox" checked={form.always_block_sanctions}
                   onChange={(e) => setForm({ ...form, always_block_sanctions: e.target.checked })} />
            Always block wallets on a sanctions list
          </label>
        </fieldset>
        {invalid && <div className="err">The block level must be higher than the hold level.</div>}
        {save.isError && <ErrorBox error={save.error} />}
        {save.isSuccess && <p className="verified">Saved. The change is in the audit log.</p>}
        {editable ? (
          <div className="actions"><button className="btn primary" disabled={invalid || save.isPending}>{save.isPending ? "Saving…" : "Save policy"}</button></div>
        ) : <p className="muted">{can("policy.edit")
              ? "Turn on two-factor authentication (My account) to change the policy."
              : "Your role can view the policy but not change it."}</p>}
      </form>
    </>
  );
}
