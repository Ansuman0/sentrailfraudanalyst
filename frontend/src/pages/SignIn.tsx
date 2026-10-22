import { useState, type FormEvent } from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { Logo } from "../components/Logo";
import { useAuth } from "../hooks/useAuth";
import { ApiError } from "../services/http";
import { auth } from "../services/sentrail";
import { safeReturnPath } from "../utils/format";

// Codes the API puts on /signin?error= after a failed OIDC sign-in (app/admin_api.py _fail()).
const OIDC_ERRORS: Record<string, string> = {
  cancelled: "Sign-in was cancelled.",
  expired: "That sign-in link expired. Start again.",
  invalid: "Sign-in couldn't be verified. Start again.",
  no_account: "There's no Sentrail account for that identity. Ask your admin for an invitation.",
  suspended: "Your account is suspended. Contact your admin.",
};

export function SignIn() {
  const { status, completeSignIn } = useAuth();
  const [params] = useSearchParams();
  const returnTo = safeReturnPath(params.get("return_to"));
  const [step, setStep] = useState<"password" | "mfa">("password");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaToken, setMfaToken] = useState("");
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(OIDC_ERRORS[params.get("error") ?? ""] ?? null);

  if (status === "signed_in") return <Navigate to={returnTo} replace />;

  // Every failure gets a plain sentence. Wrong email and wrong password look the same on purpose (the API never says
  // which one was wrong, or whether an account exists), so the hint points to the invitation instead.
  const fail = (e: unknown) => {
    if (!(e instanceof ApiError)) return setError("Sign-in failed. Try again");
    if (e.status === 0) return setError(e.message);
    if (e.status === 422) return setError("Enter a valid email address and your password.");
    if (e.status === 429) return setError("Too many attempts. Wait a few minutes, then try again.");
    if (e.status >= 500) return setError("Something went wrong on our side. Try again in a moment.");
    if (e.status === 401 && e.message === "Email or password is incorrect")
      return setError("Email or password is incorrect. If you don't have an account yet, ask your administrator for an invitation.");
    return setError(e.message);
  };

  async function submitPassword(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const r = await auth.login(email.trim(), password);
      setPassword(""); // don't keep the password in memory longer than needed
      if ("access_token" in r) {
        await completeSignIn(r.access_token); // two-factor isn't set up yet: the app asks next
        return;
      }
      setMfaToken(r.mfa_token);
      setStep("mfa");
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const r = await auth.mfa(mfaToken, useRecovery ? { recovery_code: code.trim() } : { code: code.trim() });
      await completeSignIn(r.access_token);
    } catch (err) {
      fail(err);
      if (err instanceof ApiError && err.message.startsWith("Sign-in expired")) setStep("password");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <div className="card">
        <div className="logo"><Logo size={36} /></div>
        <h1>Sign in to Sentrail</h1>
        {step === "password" ? (
          <form onSubmit={submitPassword} noValidate>
            <p className="lsub">Use your work email, like name@sentrail.qatech.world.</p>
            <div className="field">
              <label htmlFor="email">Email</label>
              <input id="email" type="email" autoComplete="username" required value={email}
                     placeholder="name@sentrail.qatech.world"
                     onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="password">Password</label>
              <input id="password" type="password" autoComplete="current-password" required value={password}
                     maxLength={256} onChange={(e) => setPassword(e.target.value)} />
            </div>
            {error && <div className="err" role="alert">{error}</div>}
            <button className="btn primary full" disabled={busy || !email || !password}>
              {busy ? "Signing in…" : "Continue"}
            </button>
          </form>
        ) : (
          <form onSubmit={submitCode} noValidate>
            <p className="lsub">
              {useRecovery ? "Enter one of your recovery codes." : "Enter the 6-digit code from your authenticator app."}
            </p>
            <div className="field">
              <label htmlFor="code">{useRecovery ? "Recovery code" : "Code"}</label>
              <input id="code" autoComplete="one-time-code" inputMode={useRecovery ? "text" : "numeric"} required
                     autoFocus maxLength={useRecovery ? 12 : 6} value={code}
                     onChange={(e) => setCode(e.target.value)} />
            </div>
            {error && <div className="err" role="alert">{error}</div>}
            <button className="btn primary full" disabled={busy || !code}>{busy ? "Verifying…" : "Verify"}</button>
            <button type="button" className="linkbtn lforgot" onClick={() => { setUseRecovery(!useRecovery); setCode(""); }}>
              {useRecovery ? "Use an authenticator code instead" : "Use a recovery code"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

export function SignedOut() {
  return (
    <div className="login">
      <div className="card">
        <div className="logo"><Logo size={36} /></div>
        <h1>You're signed out</h1>
        <p className="lsub">Your session has ended.</p>
        <a className="btn primary full" href="/signin">Sign in again</a>
      </div>
    </div>
  );
}
