import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Empty, ErrorBox, Loading, PageHeader } from "../components/common";
import { admin } from "../services/sentrail";
import { fmtDateTime } from "../utils/format";

export function ApiKeys() {
  const qc = useQueryClient();
  const keys = useQuery({ queryKey: ["api-keys"], queryFn: admin.apiKeys });
  const [label, setLabel] = useState("");
  const [days, setDays] = useState("");
  const [confirming, setConfirming] = useState<string | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["api-keys"] });

  // The new key is shown once, from the mutation result only: it is never put in the query cache or storage.
  const create = useMutation({
    mutationFn: () => admin.createApiKey(label.trim(), days ? { expires_in_days: Number(days) } : {}),
    onSuccess: () => { setLabel(""); setDays(""); refresh(); },
  });
  const rotate = useMutation({ mutationFn: (prefix: string) => admin.rotateApiKey(prefix), onSuccess: refresh });
  const revoke = useMutation({ mutationFn: (prefix: string) => admin.revokeApiKey(prefix), onSuccess: () => { setConfirming(null); refresh(); } });
  const onCreate = (e: FormEvent) => { e.preventDefault(); create.mutate(); };

  return (
    <>
      <PageHeader title="API keys" sub="Keys let your payment system call the screening API. A key is shown once when it is created and can only be revoked, not viewed again." />
      <form className="panel narrow" onSubmit={onCreate} aria-label="Create an API key">
        <div className="field">
          <label htmlFor="key-label">Label (optional)</label>
          <input id="key-label" maxLength={80} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Production payments service" />
        </div>
        <div className="field">
          <label htmlFor="key-days">Expires after (days, optional)</label>
          <input id="key-days" type="number" min={1} max={730} value={days} onChange={(e) => setDays(e.target.value)} />
        </div>
        {create.isError && <ErrorBox error={create.error} />}
        <div className="actions"><button className="btn primary" disabled={create.isPending}>{create.isPending ? "Creating…" : "Create key"}</button></div>
      </form>

      {create.isSuccess && (
        <div className="panel narrow" role="status">
          <b>Copy this key now. It won't be shown again.</b>
          <p className="mono" data-testid="new-key" style={{ wordBreak: "break-all" }}>{create.data.api_key}</p>
          <div className="actions"><button className="btn" onClick={() => create.reset()}>I've copied it</button></div>
        </div>
      )}

      {rotate.isSuccess && (
        <div className="panel narrow" role="status">
          <b>Copy the new key now. It won't be shown again.</b>
          <p className="mono" data-testid="rotated-key" style={{ wordBreak: "break-all" }}>{rotate.data.api_key}</p>
          <p className="muted">The old key keeps working until {fmtDateTime(rotate.data.old_key_expires_at)}, so your system can switch over without downtime.</p>
          <div className="actions"><button className="btn" onClick={() => rotate.reset()}>I've copied it</button></div>
        </div>
      )}
      {rotate.isError && <ErrorBox error={rotate.error} />}
      <h2>Keys</h2>
      {revoke.isError && <ErrorBox error={revoke.error} />}
      {keys.isPending ? <Loading /> : keys.isError ? <ErrorBox error={keys.error} /> : keys.data.length === 0 ? <Empty>No API keys yet.</Empty> : (
        <div className="tablewrap">
          <table>
            <thead><tr><th>Key</th><th>Label</th><th>Created</th><th>Expires</th><th>Last used</th><th>Status</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {keys.data.map((k) => (
                <tr key={k.prefix}>
                  <td className="mono">{k.prefix}…</td>
                  <td>{k.label ?? "—"}</td>
                  <td>{fmtDateTime(k.created_at)}</td>
                  <td>{k.expires_at ? fmtDateTime(k.expires_at) : "Never"}</td>
                  <td>{k.last_used_at ? fmtDateTime(k.last_used_at) : "—"}</td>
                  <td>{k.active ? "Active" : `Revoked ${fmtDateTime(k.revoked_at)}`}</td>
                  <td>
                    {k.active && <><button className="btn" disabled={rotate.isPending} onClick={() => rotate.mutate(k.prefix)}>Rotate</button>{" "}</>}
                    {k.active && confirming !== k.prefix && <button className="btn danger" onClick={() => setConfirming(k.prefix)}>Revoke</button>}
                    {k.active && confirming === k.prefix && (
                      <>
                        <button className="btn danger" disabled={revoke.isPending} onClick={() => revoke.mutate(k.prefix)}>Yes, revoke it</button>{" "}
                        <button className="btn" onClick={() => setConfirming(null)}>Cancel</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
