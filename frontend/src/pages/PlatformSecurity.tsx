import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ErrorBox, Loading, PageHeader } from "../components/common";
import { platform } from "../services/sentrail";
import type { PlatformSecurity as Settings } from "../types/api";

interface Form { min_password_len_floor: string; max_idle_timeout_min: string; retention_years_floor: string }

const toForm = (s: Settings): Form => ({
  min_password_len_floor: String(s.min_password_len_floor),
  max_idle_timeout_min: String(s.max_idle_timeout_min),
  retention_years_floor: String(s.retention_years_floor),
});

/**
 * The minimum every organization must meet. The API's PUT replaces the whole object and resets anything left out, so
 * the values this screen doesn't edit are sent back exactly as loaded.
 */
export function PlatformSecurity() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["platform-security"], queryFn: platform.security });
  const [form, setForm] = useState<Form | null>(null);
  const [confirming, setConfirming] = useState(false);
  useEffect(() => { if (q.data) setForm(toForm(q.data)); }, [q.data]);
  const save = useMutation({
    mutationFn: (s: Settings) => platform.setSecurity({
      min_password_len_floor: Number(form!.min_password_len_floor),
      max_idle_timeout_min: Number(form!.max_idle_timeout_min),
      retention_years_floor: Number(form!.retention_years_floor),
      max_session_hours: s.max_session_hours,
      passkeys_allowed: s.passkeys_allowed,
      platform_staff_passkey_only: s.platform_staff_passkey_only,
      allowed_regions: s.allowed_regions,
    }),
    onSuccess: () => { setConfirming(false); qc.invalidateQueries({ queryKey: ["platform-security"] }); },
  });

  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} title="The security baseline couldn't be loaded" />;
  if (!form) return null;
  const s = q.data;
  const changed = toForm(s).min_password_len_floor !== form.min_password_len_floor
    || toForm(s).max_idle_timeout_min !== form.max_idle_timeout_min
    || toForm(s).retention_years_floor !== form.retention_years_floor;
  const set = (k: keyof Form) => (e: React.ChangeEvent<HTMLInputElement>) => { setConfirming(false); setForm({ ...form, [k]: e.target.value }); };
  const onSubmit = (e: FormEvent) => { e.preventDefault(); setConfirming(true); };

  return (
    <>
      <PageHeader title="Security baseline" sub="The minimum every organization must meet. Organizations may be stricter, never weaker." />
      <form className="panel narrow" onSubmit={onSubmit}>
        <div className="fields2">
          <div className="field">
            <label htmlFor="pw">Shortest allowed password (characters)</label>
            <input id="pw" type="number" min={12} max={64} required value={form.min_password_len_floor} onChange={set("min_password_len_floor")} />
            <small>12 to 64.</small>
          </div>
          <div className="field">
            <label htmlFor="idle">Longest allowed inactivity (minutes)</label>
            <input id="idle" type="number" min={5} max={60} required value={form.max_idle_timeout_min} onChange={set("max_idle_timeout_min")} />
            <small>5 to 60.</small>
          </div>
          <div className="field">
            <label htmlFor="ret">Shortest audit retention (years)</label>
            <input id="ret" type="number" min={5} max={15} required value={form.retention_years_floor} onChange={set("retention_years_floor")} />
            <small>5 to 15.</small>
          </div>
        </div>
        {save.isError && <ErrorBox error={save.error} />}
        {confirming && (
          <div className="alertbox" role="alert" aria-label="Confirm baseline change">
            <b>This applies to every organization now.</b> Organizations below the new baseline are raised to it; stricter ones keep their own settings.
            <div className="actions">
              <button type="button" className="btn" onClick={() => setConfirming(false)}>Cancel</button>
              <button type="button" className="btn primary" disabled={save.isPending} onClick={() => save.mutate(s)}>{save.isPending ? "Applying…" : "Apply to all organizations"}</button>
            </div>
          </div>
        )}
        {save.isSuccess && !changed && <p className="verified">Saved. {save.data.tenants_checked} organizations checked. The change is in the audit log.</p>}
        {!confirming && <div className="actions"><button className="btn primary" disabled={!changed}>Review change</button></div>}
      </form>

      <h2>Reference</h2>
      <p className="muted">These are shown for reference and are not changed here.</p>
      <dl className="panel narrow">
        <dt>Longest session</dt><dd>{s.max_session_hours} hours</dd>
        <dt>Passkeys allowed</dt><dd>{s.passkeys_allowed ? "Yes" : "No"} (recorded, not yet enforced by the API)</dd>
        <dt>Platform staff passkey only</dt><dd>{s.platform_staff_passkey_only ? "Yes" : "No"} (recorded, not yet enforced by the API)</dd>
        <dt>Data regions</dt><dd>{s.allowed_regions.join(", ")}</dd>
        <dt>Two-factor</dt><dd>{s.mfa}</dd>
      </dl>
    </>
  );
}
