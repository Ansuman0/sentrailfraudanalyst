import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Empty, ErrorBox, Loading, PageHeader } from "../components/common";
import { admin, teamsApi } from "../services/sentrail";

/** Teams and queues (optional). A queue narrows what a member looks at; it never gives anyone access to a case they couldn't open before. */
function TeamEditor({ id, name, onChanged }: { id: string; name: string; onChanged: () => void }) {
  const detail = useQuery({ queryKey: ["team", id], queryFn: () => teamsApi.get(id) });
  const users = useQuery({ queryKey: ["admin-users"], queryFn: admin.users });
  const [chosen, setChosen] = useState<string[] | null>(null);
  const members = chosen ?? (detail.data?.members.map((m) => m.user_id) ?? []);
  const save = useMutation({ mutationFn: () => teamsApi.setMembers(id, members), onSuccess: () => { setChosen(null); onChanged(); void detail.refetch(); } });
  const rename = useMutation({ mutationFn: (n: string) => teamsApi.rename(id, n), onSuccess: onChanged });
  const remove = useMutation({ mutationFn: () => teamsApi.remove(id), onSuccess: onChanged });
  const [newName, setNewName] = useState(name);
  const toggle = (uid: string, on: boolean) => setChosen(on ? [...members, uid] : members.filter((x) => x !== uid));
  return (
    <section className="panel narrow" aria-label={`Team ${name}`}>
      <form onSubmit={(e) => { e.preventDefault(); rename.mutate(newName.trim()); }} className="fields2">
        <div className="field">
          <label htmlFor={`team-name-${id}`}>Team name</label>
          <input id={`team-name-${id}`} value={newName} minLength={2} maxLength={60} onChange={(e) => setNewName(e.target.value)} />
        </div>
        <div className="actions"><button className="btn" disabled={rename.isPending || newName.trim() === name || newName.trim().length < 2}>Rename</button></div>
      </form>
      <fieldset>
        <legend>Members</legend>
        {detail.isPending || users.isPending ? <Loading /> : (users.data ?? []).filter((u) => u.status === "active").map((u) => (
          <label key={u.id} className="toggle">
            <input type="checkbox" checked={members.includes(u.id)} onChange={(e) => toggle(u.id, e.target.checked)} />
            <span>{u.name ?? u.email} <span className="muted">· {u.role}</span></span>
          </label>
        ))}
      </fieldset>
      {(save.isError || rename.isError || remove.isError) && <ErrorBox error={save.error ?? rename.error ?? remove.error} />}
      <div className="actions">
        <button className="btn primary" disabled={chosen === null || save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Save members"}</button>
        <button className="btn danger" disabled={remove.isPending} onClick={() => remove.mutate()}>Delete team</button>
      </div>
      <p className="muted">Deleting a team empties its queue; the alerts stay.</p>
    </section>
  );
}

export function Teams() {
  const qc = useQueryClient();
  const teams = useQuery({ queryKey: ["teams"], queryFn: teamsApi.list });
  const [name, setName] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["teams"] }); };
  const create = useMutation({ mutationFn: () => teamsApi.create(name.trim()), onSuccess: () => { setName(""); refresh(); } });
  const onCreate = (e: FormEvent) => { e.preventDefault(); create.mutate(); };
  return (
    <>
      <PageHeader title="Teams" sub="Group people into queues. Alerts placed in a team's queue show up for its members; nobody gets access to a case they couldn't already open." />
      <form className="panel narrow" onSubmit={onCreate} aria-label="Create a team">
        <div className="field">
          <label htmlFor="team-new">New team</label>
          <input id="team-new" value={name} minLength={2} maxLength={60} onChange={(e) => setName(e.target.value)} placeholder="e.g. Night shift" />
        </div>
        {create.isError && <ErrorBox error={create.error} />}
        <div className="actions"><button className="btn primary" disabled={create.isPending || name.trim().length < 2}>Create team</button></div>
      </form>
      {teams.isPending ? <Loading /> : teams.isError ? <ErrorBox error={teams.error} /> : teams.data.length === 0 ? <Empty>No teams yet.</Empty> : (
        teams.data.map((t) => (
          <div key={t.id}>
            <p><b>{t.name}</b> <span className="muted">· {t.members} members · {t.open_alerts} open alerts</span>{" "}
              <button className="btn" onClick={() => setOpen(open === t.id ? null : t.id)}>{open === t.id ? "Close" : "Edit"}</button></p>
            {open === t.id && <TeamEditor id={t.id} name={t.name} onChanged={() => { refresh(); }} />}
          </div>
        ))
      )}
    </>
  );
}
