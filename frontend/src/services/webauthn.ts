/** The browser side of passkeys: turn the API's JSON options into WebAuthn calls and the results back into JSON. */

const toBuffer = (s: string): ArrayBuffer => {
  const b = atob((s + "=".repeat((4 - (s.length % 4)) % 4)).replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out.buffer;
};

const toBase64Url = (buf: ArrayBuffer): string => {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

export const passkeysSupported = () => typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;

/** A plain sentence for what went wrong in the browser (cancelled prompt, no authenticator, wrong site). */
export function passkeyErrorMessage(e: unknown): string {
  const name = (e as { name?: string })?.name;
  if (name === "NotAllowedError") return "The passkey prompt was cancelled or timed out. Try again.";
  if (name === "InvalidStateError") return "This device already has a passkey for your account.";
  if (name === "SecurityError") return "Passkeys don't work on this address. Open Sentrail on its normal address.";
  if (name === "NotSupportedError") return "This device or browser can't create passkeys.";
  return "Couldn't use the passkey. Try again.";
}

type Descriptor = { id: string; type: string; transports?: string[] };

export async function createPasskey(options: Record<string, any>): Promise<Record<string, unknown>> {
  const publicKey = {
    ...options,
    challenge: toBuffer(options.challenge),
    user: { ...options.user, id: toBuffer(options.user.id) },
    excludeCredentials: ((options.excludeCredentials ?? []) as Descriptor[]).map((c) => ({ ...c, id: toBuffer(c.id) })),
  } as unknown as PublicKeyCredentialCreationOptions;
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was created");
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id, rawId: toBase64Url(cred.rawId), type: cred.type, clientExtensionResults: cred.getClientExtensionResults(),
    response: { clientDataJSON: toBase64Url(r.clientDataJSON), attestationObject: toBase64Url(r.attestationObject), transports: r.getTransports?.() ?? [] },
  };
}

export async function getPasskey(options: Record<string, any>): Promise<Record<string, unknown>> {
  const publicKey = {
    ...options,
    challenge: toBuffer(options.challenge),
    allowCredentials: ((options.allowCredentials ?? []) as Descriptor[]).map((c) => ({ ...c, id: toBuffer(c.id) })),
  } as unknown as PublicKeyCredentialRequestOptions;
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was chosen");
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id, rawId: toBase64Url(cred.rawId), type: cred.type, clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: toBase64Url(r.clientDataJSON), authenticatorData: toBase64Url(r.authenticatorData),
      signature: toBase64Url(r.signature), userHandle: r.userHandle ? toBase64Url(r.userHandle) : null,
    },
  };
}
