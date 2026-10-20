import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ErrorBox, Loading, PageHeader } from "../components/common";
import { admin, type SecurityPatch } from "../services/sentrail";
import type { SecuritySettings } from "../types/api";

interface Form {
  mfa_required: boolean;
  idle_timeout_min: string;
  min_password_len: string;
  retention_years: string;
  ip_allowlist: string; // one network per line
}

const toForm = (s: SecuritySettings): Form => ({
  mfa_required: s.mfa_required,
  idle_timeout_min: String(s.idle_timeout_min),
  min_password_len: String(s.min_password_len),
  retention_years: String(s.retention_years),
  ip_allowlist: s.ip_allowlist.join("\n"),
});

const parseNetworks = (text: string) => text.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

/** Only what the person changed is sent, so a stale form can't overwrite a setting someone else changed. */
function diff(form: Form, s: SecuritySettings): SecurityPatch {
  const patch: SecurityPatch = {};
  if (form.mfa_required !== s.mfa_required) patch.mfa_required = form.mfa_required;
  if (Number(form.idle_timeout_min) !== s.idle_timeout_min) patch.idle_timeout_min = Number(form.idle_timeout_min);
  if (Number(form.min_password_len) !== s.min_password_len) patch.min_password_len = Number(form.min_password_len);
  if (Number(form.retention_years) !== s.retention_years) patch.retention_years = Number(form.retention_years);
  const nets = parseNetworks(form.ip_allowlist);
  if (nets.join() !== s.ip_allowlist.join()) patch.ip_allowlist = nets;
  return patch;
}

export function Security() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["admin-security"], queryFn: admin.security });
  const [form, setForm] = useState<Form | null>(null);
  useEffect(() => { if (q.data) setForm(toForm(q.data)); }, [q.data]);
  const save = useMutation({
    mutationFn: (patch: SecurityPatch) => admin.setSecurity(patch),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin-security"] }),
  });

  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} title="Security settings couldn't be loaded" />;
  if (!form) return null;
  const s = q.data;
  const patch = diff(form, s);
  const changed = Object.keys(patch).length > 0;
  const set = (k: keyof Form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setForm({ ...form, [k]: e.target.value });
  const onSubmit = (e: FormEvent) => { e.preventDefault(); save.mutate(patch); };

  return (
    <>
      <PageHeader title="Security settings" sub="How people in your organization sign in and how long records are kept. Every change is recorded in the audit log." />
      <form className="panel narrow" onSubmit={onSubmit}>
        <label className="toggle">
          <input type="checkbox" checked={form.mfa_required} onChange={(e) => setForm({ ...form, mfa_required: e.target.checked })} />
          <span>
            <b>Require two-factor authentication for everyone</b><br />
            <span className="muted">When on, people without two-factor are taken to the setup screen at their next sign-in and can't continue
            until it is done. When off, it is optional, except for administrators and for approving STRs, exporting data, editing policy and overriding screening.</span>
          </span>
        </label>
        <div className="fields2">
          <div className="field">
            <label htmlFor="idle">Sign out after inactivity (minutes)</label>
            <input id="idle" type="number" min={5} max={60} required value={form.idle_timeout_min} onChange={set("idle_timeout_min")} />
            <small>5 to 60. Your Sentrail contact may set a lower ceiling.</small>
          </div>
          <div className="field">
            <label htmlFor="pwlen">Minimum password length</label>
            <input id="pwlen" type="number" min={12} max={64} required value={form.min_password_len} onChange={set("min_password_len")} />
            <small>12 to 64 characters. Applies to new passwords.</small>
          </div>
          <div className="field">
            <label htmlFor="retention">Keep audit records for (years)</label>
            <input id="retention" type="number" min={5} max={15} required value={form.retention_years} onChange={set("retention_years")} />
            <small>5 to 15 years.</small>
          </div>
        </div>
        <div className="field">
          <label htmlFor="allow">Allowed networks</label>
          <textarea id="allow" rows={3} value={form.ip_allowlist} onChange={set("ip_allowlist")} placeholder="203.0.113.0/24" />
          <small>One network (CIDR) per line. Leave empty to allow any network. Sentrail won't save a list that would lock you out.</small>
        </div>
        {save.isError && <ErrorBox error={save.error} />}
        {save.isSuccess && !changed && <p className="verified">Saved. The change is in the audit log.</p>}
        <div className="actions"><button className="btn primary" disabled={!changed || save.isPending}>{save.isPending ? "Saving…" : "Save"}</button></div>
      </form>

      <h2>Reference</h2>
      <dl className="panel narrow">
        <dt>Company single sign-on</dt><dd>{s.sso_enabled ? "On" : "Off"} (set up through your Sentrail administrator for now)</dd>
        <dt>Encryption</dt><dd>{s.encryption.algorithm}, key {s.encryption.current_key}, managed by {s.encryption.key_manager}</dd>
      </dl>
    </>
  );
}
