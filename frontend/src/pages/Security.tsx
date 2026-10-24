import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ErrorBox, Loading, PageHeader } from "../components/common";
import { admin, governance, type SecurityPatch } from "../services/sentrail";
import { useAuth } from "../hooks/useAuth";
import type { SecuritySettings } from "../types/api";

interface Form {
  mfa_required: boolean;
  idle_timeout_min: string;
  min_password_len: string;
  retention_years: string;
  ip_allowlist: string; // one network per line
  dormant_days: string;
  access_review_days: string;
  export_limit_per_hour: string;
  anomaly_searches_per_hour: string;
  anomaly_exports_per_hour: string;
  alert_new_country: boolean;
  owner_access: "allow" | "require_approval" | "deny";
}

const toForm = (s: SecuritySettings): Form => ({
  mfa_required: s.mfa_required,
  idle_timeout_min: String(s.idle_timeout_min),
  min_password_len: String(s.min_password_len),
  retention_years: String(s.retention_years),
  ip_allowlist: s.ip_allowlist.join("\n"),
  dormant_days: String(s.dormant_days),
  access_review_days: String(s.access_review_days),
  export_limit_per_hour: String(s.export_limit_per_hour),
  anomaly_searches_per_hour: String(s.anomaly_searches_per_hour),
  anomaly_exports_per_hour: String(s.anomaly_exports_per_hour),
  alert_new_country: s.alert_new_country,
  owner_access: s.owner_access ?? "allow",
});

const parseNetworks = (text: string) => text.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

/** Only what the person changed is sent, so a stale form can't overwrite a setting someone else changed. */
function diff(form: Form, s: SecuritySettings): SecurityPatch {
  const patch: SecurityPatch = {};
  if (form.mfa_required !== s.mfa_required) patch.mfa_required = form.mfa_required;
  if (Number(form.idle_timeout_min) !== s.idle_timeout_min) patch.idle_timeout_min = Number(form.idle_timeout_min);
  if (Number(form.min_password_len) !== s.min_password_len) patch.min_password_len = Number(form.min_password_len);
  if (Number(form.retention_years) !== s.retention_years) patch.retention_years = Number(form.retention_years);
  for (const k of ["dormant_days", "access_review_days", "export_limit_per_hour", "anomaly_searches_per_hour", "anomaly_exports_per_hour"] as const) {
    if (Number(form[k]) !== s[k]) patch[k] = Number(form[k]);
  }
  if (form.alert_new_country !== s.alert_new_country) patch.alert_new_country = form.alert_new_country;
  if (form.owner_access !== (s.owner_access ?? "allow")) patch.owner_access = form.owner_access;
  const nets = parseNetworks(form.ip_allowlist);
  if (nets.join() !== s.ip_allowlist.join()) patch.ip_allowlist = nets;
  return patch;
}

/** The whole organization's data as one signed file, for leaving or moving. Fetched once through a link that lasts 15 minutes. */
function DataExport() {
  const { can } = useAuth();
  const [note, setNote] = useState<string | null>(null);
  const run = useMutation({
    mutationFn: async () => {
      const link = await governance.exportData();
      const text = await governance.download(link.download_path);
      const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
      const a = document.createElement("a");
      a.href = url; a.download = link.filename; a.click();
      URL.revokeObjectURL(url);
      return link;
    },
    onSuccess: (l) => setNote(`Downloaded ${l.filename}. The download link is now used up.`),
  });
  if (!can("data.export")) return null;
  return (
    <>
      <h2>Your data</h2>
      <div className="panel narrow">
        <p>Export everything your organization has in Sentrail: people, roles, cases, STRs, screenings, settings and the audit log, in one signed file. Passwords, authenticator seeds, API key hashes and passkeys are never included.</p>
        {run.isError && <ErrorBox error={run.error} />}
        {note && <p className="verified" role="status">{note}</p>}
        <div className="actions"><button className="btn" disabled={run.isPending} onClick={() => run.mutate()}>{run.isPending ? "Preparing…" : "Export all data"}</button></div>
      </div>
    </>
  );
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
        <h2>Sentrail staff access</h2>
        <div className="field">
          <label htmlFor="owner-access">When a Sentrail platform owner asks to enter your organization</label>
          <select id="owner-access" value={form.owner_access} onChange={(e) => setForm({ ...form, owner_access: e.target.value as Form["owner_access"] })}>
            <option value="allow">Start the session at once (you are told)</option>
            <option value="require_approval">Wait for one of your administrators to approve</option>
            <option value="deny">Refuse (only a recorded legal hold overrides)</option>
          </select>
          <small>Sessions last 60 minutes and everything done in them is in your audit log. Requests are listed under Platform access requests.</small>
        </div>
        <h2>Governance</h2>
        <div className="fields2">
          <div className="field">
            <label htmlFor="dormant">Suspend people unused for (days)</label>
            <input id="dormant" type="number" min={30} max={365} required value={form.dormant_days} onChange={set("dormant_days")} />
            <small>30 to 365. The last administrator is never suspended.</small>
          </div>
          <div className="field">
            <label htmlFor="reviewdays">Open an access review every (days)</label>
            <input id="reviewdays" type="number" min={30} max={365} required value={form.access_review_days} onChange={set("access_review_days")} />
            <small>30 to 365.</small>
          </div>
          <div className="field">
            <label htmlFor="exportlimit">Exports per person per hour</label>
            <input id="exportlimit" type="number" min={1} max={1000} required value={form.export_limit_per_hour} onChange={set("export_limit_per_hour")} />
          </div>
          <div className="field">
            <label htmlFor="alertsearch">Alert admins past this many searches an hour</label>
            <input id="alertsearch" type="number" min={5} max={10000} required value={form.anomaly_searches_per_hour} onChange={set("anomaly_searches_per_hour")} />
          </div>
          <div className="field">
            <label htmlFor="alertexport">Alert admins past this many exports an hour</label>
            <input id="alertexport" type="number" min={1} max={1000} required value={form.anomaly_exports_per_hour} onChange={set("anomaly_exports_per_hour")} />
          </div>
        </div>
        <label className="toggle">
          <input type="checkbox" checked={form.alert_new_country} onChange={(e) => setForm({ ...form, alert_new_country: e.target.checked })} />
          <span><b>Alert admins when someone signs in from a new country</b></span>
        </label>
        {save.isError && <ErrorBox error={save.error} />}
        {save.isSuccess && !changed && <p className="verified">Saved. The change is in the audit log.</p>}
        <div className="actions"><button className="btn primary" disabled={!changed || save.isPending}>{save.isPending ? "Saving…" : "Save"}</button></div>
      </form>

      <DataExport />
      <h2>Reference</h2>
      <dl className="panel narrow">
        <dt>Company single sign-on</dt><dd>{s.sso_enabled ? "On" : "Off"} (set up through your Sentrail administrator for now)</dd>
        <dt>Encryption</dt><dd>{s.encryption.algorithm}, key {s.encryption.current_key}, managed by {s.encryption.key_manager}</dd>
      </dl>
    </>
  );
}
