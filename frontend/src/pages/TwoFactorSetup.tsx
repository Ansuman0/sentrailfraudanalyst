import { useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ErrorBox } from "../components/common";
import { PasskeyRegister } from "../components/PasskeyRegister";
import { QrCode } from "../components/QrCode";
import { Logo } from "../components/Logo";
import { useAuth } from "../hooks/useAuth";
import { me as meApi } from "../services/sentrail";
import { safeReturnPath } from "../utils/format";

/**
 * Turn on two-factor, from My account. Optional by default ("Not now" goes back); only when the organization has made
 * it mandatory (/me.mfa_setup = "required") is there no way past it. Setup starts from a button rather than on page
 * load, so it never creates two secrets. The QR code and the typed key are the same secret.
 */
export function TwoFactorSetup() {
  const { me, completeSignIn, signOut } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const next = safeReturnPath(params.get("return_to") ?? "/account");
  const [setup, setSetup] = useState<{ otpauth_uri: string; secret: string } | null>(null);
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const required = me?.mfa_setup === "required";

  const run = async (fn: () => Promise<void>) => {
    setError(null);
    setBusy(true);
    try { await fn(); } catch (e) { setError(e); } finally { setBusy(false); }
  };
  const start = () => run(async () => setSetup(await meApi.mfaSetup()));
  const confirm = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const r = await meApi.mfaConfirm(code.trim());
      setRecovery(r.recovery_codes);   // show these before the new session re-renders the app
      await completeSignIn(r.access_token);
    });
  };
  const skip = () => navigate(next, { replace: true });

  if (recovery) {
    return (
      <Card title="Two-factor is on">
        <p className="lsub">Save these recovery codes somewhere safe. Each works once if you lose your phone, and they won't be shown again.</p>
        <pre className="codes mono">{recovery.join("\n")}</pre>
        <button className="btn primary full" onClick={() => navigate(next, { replace: true })}>Continue</button>
      </Card>
    );
  }
  if (me?.mfa_setup == null) {
    // Opened directly when two-factor is already on (or the sign-in provider handles it).
    return (
      <Card title="Two-factor authentication">
        <p className="lsub">Two-factor is already on for your account.</p>
        <button className="btn primary full" onClick={() => navigate(next, { replace: true })}>Continue</button>
      </Card>
    );
  }
  return (
    <Card title="Set up two-factor authentication">
      {!setup ? (
        <>
          <p className="lsub">
            {required
              ? "Your organization requires a code from an authenticator app each time you sign in. Set it up to continue."
              : "Protect your account with a code from an authenticator app each time you sign in. It's your choice; without it you can't approve STRs, export cases, change the screening policy or override a held screening."}
          </p>
          {error != null && <ErrorBox error={error} />}
          <button className="btn primary full" disabled={busy} onClick={() => void start()}>
            {busy ? "Starting…" : "Set up now"}
          </button>
          <div className="lor">or</div>
          <p className="lsub">Use a passkey instead: your device's fingerprint, face or PIN.</p>
          <PasskeyRegister />
          {required ? (
            <button type="button" className="linkbtn lforgot" onClick={() => void signOut()}>Sign out</button>
          ) : (
            <button type="button" className="btn full skip" onClick={skip}>Not now</button>
          )}
        </>
      ) : (
        <form onSubmit={confirm} noValidate>
          <p className="lsub">Scan this QR code with your authenticator app (Google Authenticator, Microsoft Authenticator, 1Password…), then enter the 6-digit code it shows.</p>
          <div className="qrbox"><QrCode value={setup.otpauth_uri} label="QR code to add Sentrail to your authenticator app" /></div>
          <div className="field">
            <label htmlFor="setupkey">Can't scan? Type this key instead</label>
            <input id="setupkey" className="mono" readOnly value={setup.secret} onFocus={(e) => e.target.select()} />
            <small><a href={setup.otpauth_uri}>Open in an authenticator app on this device</a></small>
          </div>
          <div className="field">
            <label htmlFor="code">Code</label>
            <input id="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} autoFocus value={code}
                   onChange={(e) => setCode(e.target.value)} />
          </div>
          {error != null && <ErrorBox error={error} />}
          <button className="btn primary full" disabled={busy || code.trim().length !== 6}>{busy ? "Checking…" : "Turn on two-factor"}</button>
          {!required && <button type="button" className="btn full skip" onClick={skip}>Cancel</button>}
        </form>
      )}
    </Card>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="login">
      <div className="card">
        <div className="logo"><Logo size={36} /></div>
        <h1>{title}</h1>
        {children}
      </div>
    </div>
  );
}
