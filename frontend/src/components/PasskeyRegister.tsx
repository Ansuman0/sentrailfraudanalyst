import { useState, type FormEvent } from "react";
import { useAuth } from "../hooks/useAuth";
import { ApiError } from "../services/http";
import { passkeys } from "../services/sentrail";
import { createPasskey, passkeyErrorMessage, passkeysSupported } from "../services/webauthn";

/** Name it, then the browser asks for the fingerprint, face or PIN. When it is the first second factor the API answers with a new session. */
export function PasskeyRegister({ onDone }: { onDone?: () => void }) {
  const { completeSignIn } = useAuth();
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!passkeysSupported()) return <p className="sub">This browser can't create passkeys.</p>;

  async function add(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const options = await passkeys.options();
      const credential = await createPasskey(options);
      const made = await passkeys.register(credential, name.trim() || "Passkey");
      setName("");
      if (made.session) await completeSignIn(made.session.access_token);
      onDone?.();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : passkeyErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={add} aria-label="Add a passkey">
      <div className="field">
        <label htmlFor="passkey-name">Name this passkey</label>
        <input id="passkey-name" value={name} maxLength={60} placeholder="Work laptop" onChange={(e) => setName(e.target.value)} />
      </div>
      {error && <div className="err" role="alert">{error}</div>}
      <div className="actions"><button className="btn primary" disabled={busy}>{busy ? "Waiting for your device…" : "Add a passkey"}</button></div>
    </form>
  );
}
