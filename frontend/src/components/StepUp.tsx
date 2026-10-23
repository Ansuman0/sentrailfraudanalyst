import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { ApiError, setAccessToken, setStepUpHandler } from "../services/http";
import { useAuth } from "../hooks/useAuth";
import { auth } from "../services/sentrail";
import { getPasskey, passkeyErrorMessage, passkeysSupported } from "../services/webauthn";

/**
 * Step-up: the API answers 401 {"error": "step_up_required"} when a sensitive action needs a fresh second factor. http.ts
 * calls the handler registered here, which asks for a code, and repeats the original call once the API accepted it.
 * Several calls failing at once share one prompt.
 */
export function StepUpProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const pending = useRef<{ promise: Promise<boolean>; resolve: (ok: boolean) => void } | null>(null);

  useEffect(() => {
    setStepUpHandler(() => {
      if (!pending.current) {
        let resolve!: (ok: boolean) => void;
        const promise = new Promise<boolean>((r) => (resolve = r));
        pending.current = { promise, resolve };
        setOpen(true);
      }
      return pending.current.promise;
    });
    return () => setStepUpHandler(null);
  }, []);

  const finish = (ok: boolean) => {
    pending.current?.resolve(ok);
    pending.current = null;
    setOpen(false);
  };

  return (
    <>
      {children}
      {open && <StepUpDialog onDone={finish} />}
    </>
  );
}

function StepUpDialog({ onDone }: { onDone: (ok: boolean) => void }) {
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { me } = useAuth();
  const hasPasskey = (me?.passkeys ?? 0) > 0 && passkeysSupported();

  async function withPasskey() {
    setBusy(true);
    setError(null);
    try {
      const r = await auth.stepUp({ credential: await getPasskey(await auth.stepUpOptions()) });
      setAccessToken(r.access_token);
      onDone(true);
    } catch (err) {
      setError(err instanceof ApiError ? "That passkey didn't work. Try again." : passkeyErrorMessage(err));
      setBusy(false);
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await auth.stepUp(useRecovery ? { recovery_code: code.trim() } : { code: code.trim() });
      setAccessToken(r.access_token);
      onDone(true);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 401 ? "That code didn't work. Check your app and try again." : "Couldn't confirm. Try again.");
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <form className="modal card" role="dialog" aria-modal="true" aria-labelledby="stepup-title" onSubmit={submit}>
        <h2 id="stepup-title">Confirm it's you</h2>
        <p className="sub">
          {useRecovery ? "Enter one of your recovery codes." : "This action needs a fresh check. Enter the 6-digit code from your authenticator app."}
        </p>
        {hasPasskey && (
          <div className="actions">
            <button type="button" className="btn primary" disabled={busy} onClick={() => void withPasskey()}>Use your passkey</button>
          </div>
        )}
        <div className="field">
          <label htmlFor="stepup-code">{useRecovery ? "Recovery code" : "Authenticator code"}</label>
          <input id="stepup-code" autoFocus autoComplete="one-time-code" inputMode={useRecovery ? "text" : "numeric"}
                 value={code} onChange={(e) => setCode(e.target.value)} maxLength={useRecovery ? 40 : 6} />
        </div>
        {error && <div className="err" role="alert">{error}</div>}
        <div className="actions">
          <button type="button" className="btn" onClick={() => onDone(false)} disabled={busy}>Cancel</button>
          <button className="btn primary" disabled={busy || !code.trim()}>{busy ? "Checking…" : "Confirm"}</button>
        </div>
        <button type="button" className="linkbtn" onClick={() => { setUseRecovery(!useRecovery); setCode(""); setError(null); }}>
          {useRecovery ? "Use my authenticator app instead" : "Use a recovery code instead"}
        </button>
      </form>
    </div>
  );
}
