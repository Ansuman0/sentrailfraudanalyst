import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ErrorBox } from "../components/common";
import { Logo } from "../components/Logo";
import { invitations } from "../services/sentrail";

/**
 * Invitation sign-up: /join#<token>. The token is in the URL fragment so it never reaches a server log.
 * Sets name and password only; two-factor is offered (or required) after the first sign-in.
 */
export function Join() {
  const [token] = useState(() => decodeURIComponent(window.location.hash.slice(1)));
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await invitations.accept(token, name.trim(), password);
      setPassword("");
      setDone(true);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <div className="card">
        <div className="logo"><Logo size={36} /></div>
        <h1>Set up your account</h1>
        {!token ? (
          <p className="lsub">This invitation link is incomplete. Open the link from your email again.</p>
        ) : done ? (
          <>
            <p className="lsub">Your account is ready. Sign in with your email and new password.</p>
            <Link className="btn primary full" to="/signin">Sign in</Link>
          </>
        ) : (
          <form onSubmit={onSubmit} noValidate>
            <p className="lsub">Choose a long password: 14 characters or more works best.</p>
            <div className="field">
              <label htmlFor="name">Full name</label>
              <input id="name" autoComplete="name" minLength={2} maxLength={120} value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="newpw">Password</label>
              <input id="newpw" type="password" autoComplete="new-password" maxLength={256} value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            {error != null && <ErrorBox error={error} />}
            <button className="btn primary full" disabled={busy || name.trim().length < 2 || !password}>{busy ? "Saving…" : "Create account"}</button>
          </form>
        )}
      </div>
    </div>
  );
}
