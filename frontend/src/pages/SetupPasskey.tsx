import { useNavigate } from "react-router-dom";
import { Logo } from "../components/Logo";
import { PasskeyRegister } from "../components/PasskeyRegister";
import { useAuth } from "../hooks/useAuth";

/** Platform owners must use a passkey: until they have one, this is the only screen that works. */
export function SetupPasskey() {
  const { signOut } = useAuth();
  const navigate = useNavigate();
  return (
    <div className="login">
      <div className="card">
        <div className="logo"><Logo size={36} /></div>
        <h1>Register a passkey</h1>
        <p className="lsub">Platform owners sign in with a passkey (your device's fingerprint, face or PIN, or a security key). Add one to continue.</p>
        <PasskeyRegister onDone={() => navigate("/", { replace: true })} />
        <button type="button" className="linkbtn" onClick={() => void signOut()}>Sign out</button>
      </div>
    </div>
  );
}
