import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ErrorBox, Loading, PageHeader } from "../components/common";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";
import { admin } from "../services/sentrail";
import type { RoleSummary } from "../types/api";
import { ORG_PERMISSIONS, permissionLabel } from "../utils/permissions";

/** Checkbox list for one role. Permissions the API returned but this app has no label for stay visible and editable. */
function PermissionPicker({ value, onChange, disabled }: { value: string[]; onChange: (v: string[]) => void; disabled?: boolean }) {
  const known = new Set(ORG_PERMISSIONS.map((p) => p.id));
  const all = [...ORG_PERMISSIONS, ...value.filter((id) => !known.has(id)).map((id) => ({ id, label: id, sensitive: false }))];
  const toggle = (id: string, on: boolean) => onChange(on ? [...value, id] : value.filter((x) => x !== id));
  return (
    <fieldset disabled={disabled}>
      <legend className="sr-only">Permissions</legend>
      {all.map((p) => (
        <label key={p.id} className="toggle">
          <input type="checkbox" checked={value.includes(p.id)} onChange={(e) => toggle(p.id, e.target.checked)} />
          <span>
            {p.label}
            {p.sensitive && <span className="muted"> · needs two-factor to use</span>}
          </span>
        </label>
      ))}
    </fieldset>
  );
}

function RoleEditor({ role, isOwn }: { role: RoleSummary; isOwn: boolean }) {
  const qc = useQueryClient();
  const { startPreview } = useAuth();
  const navigate = useNavigate();
  const preview = useMutation({ mutationFn: () => startPreview(role.id), onSuccess: () => navigate("/") });
  const [name, setName] = useState(role.name);
  const [perms, setPerms] = useState<string[]>(role.perms);
  const save = useMutation({
    mutationFn: () => admin.updateRole(role.id, name.trim(), perms),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin-roles"] }),
  });
  const changed = name !== role.name || [...perms].sort().join() !== [...role.perms].sort().join();
  const onSubmit = (e: FormEvent) => { e.preventDefault(); save.mutate(); };
  return (
    <form className="panel narrow" onSubmit={onSubmit} aria-label={`Role ${role.name}`}>
      <div className="field">
        <label htmlFor={`name-${role.id}`}>Role name</label>
        <input id={`name-${role.id}`} value={name} minLength={2} maxLength={60} onChange={(e) => setName(e.target.value)} disabled={isOwn || role.system} />
        {role.system && <small>Built-in role: the name is fixed, the permissions can change.</small>}
      </div>
      <PermissionPicker value={perms} onChange={setPerms} disabled={isOwn || role.locked} />
      {role.locked && <p className="muted">This role is locked: it always holds every permission and can't be edited.</p>}
      {isOwn && !role.locked && <p className="muted">This is your own role. Another admin has to change it.</p>}
      {save.isError && <ErrorBox error={save.error} />}
      {save.isSuccess && <p className="verified">Saved. People with this role get the change on their next request.</p>}
      {save.data?.warnings?.map((w) => <div key={w} className="alertbox" role="note">{w}</div>)}
      {preview.isError && <ErrorBox error={preview.error} />}
      <div className="actions"><button type="button" className="btn" disabled={preview.isPending} onClick={() => preview.mutate()}>Preview as {role.name}</button></div>
      {!isOwn && !role.locked && <div className="actions"><button className="btn primary" disabled={!changed || save.isPending}>{save.isPending ? "Saving…" : "Save role"}</button></div>}
    </form>
  );
}

export function Roles() {
  const { me } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["admin-roles"], queryFn: admin.roles });
  const [name, setName] = useState("");
  const [perms, setPerms] = useState<string[]>([]);
  const create = useMutation({
    mutationFn: () => admin.createRole(name.trim(), perms),
    onSuccess: () => { setName(""); setPerms([]); qc.invalidateQueries({ queryKey: ["admin-roles"] }); },
  });
  const onCreate = (e: FormEvent) => { e.preventDefault(); create.mutate(); };

  return (
    <>
      <PageHeader title="Roles" sub="What each role can do in your organization. You can't change the role you hold yourself." />
      {q.isPending ? <Loading /> : q.isError ? <ErrorBox error={q.error} /> : (
        <>
          {q.data.warnings.map((w) => <div key={w} className="alertbox" role="note">{w}</div>)}
          {q.data.roles.map((r) => <RoleEditor key={`${r.id}-${[...r.perms].sort().join()}`} role={r} isOwn={r.name === me?.role} />)}
        </>
      )}
      <h2>New custom role</h2>
      <form className="panel narrow" onSubmit={onCreate} aria-label="Create a role">
        <div className="field">
          <label htmlFor="new-role-name">Role name</label>
          <input id="new-role-name" value={name} minLength={2} maxLength={60} onChange={(e) => setName(e.target.value)} />
        </div>
        <PermissionPicker value={perms} onChange={setPerms} />
        {create.isError && <ErrorBox error={create.error} />}
        <div className="actions"><button className="btn primary" disabled={create.isPending || name.trim().length < 2}>{create.isPending ? "Creating…" : "Create role"}</button></div>
      </form>
      <p className="muted">{permissionLabel("users.manage")}, {permissionLabel("roles.manage")} and {permissionLabel("features.manage")} always need two-factor.</p>
    </>
  );
}
