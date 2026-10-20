import { useState, type FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { ErrorBox, PageHeader } from "../components/common";
import { admin } from "../services/sentrail";

/**
 * Company sign-in (SSO): prove you own an email domain with a DNS record, then people on that domain sign in through
 * your identity provider. The API doesn't let us read the current setup back, and returns the DNS record only when the
 * setup is saved, so the record is shown here once; saving again gives a new one.
 * The API's "enforced" option is stored but not enforced yet, so it isn't offered.
 */
export function Sso() {
  const [domain, setDomain] = useState("");
  const [alias, setAlias] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const setup = useMutation({ mutationFn: () => admin.setSso(domain.trim().toLowerCase(), alias.trim().toLowerCase()) });
  const verify = useMutation({ mutationFn: () => admin.verifySso() });
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    // Normalize first (people paste with spaces or capitals), then check in words the API's pattern error doesn't give.
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain.trim().toLowerCase())) return setProblem("Enter just the domain, for example northwindremit.ca (no @ and no https://).");
    if (!/^[a-z0-9-]{2,40}$/.test(alias.trim().toLowerCase())) return setProblem("The provider name can only use letters, numbers and hyphens (2 to 40 characters).");
    setProblem(null);
    verify.reset();
    setup.mutate();
  };

  return (
    <>
      <PageHeader title="Company sign-in" sub="Let people with your company email sign in through your own identity provider (Entra ID, Google, Okta…)." />
      <p className="muted">Needs an identity provider connected in Keycloak first. Sentrail checks that you control the email domain before using it.</p>
      <form className="panel narrow" onSubmit={onSubmit} aria-label="Company sign-in setup">
        <div className="field">
          <label htmlFor="sso-domain">Email domain</label>
          <input id="sso-domain" required placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} />
          <small>Only the part after the @, for example northwindremit.ca.</small>
        </div>
        <div className="field">
          <label htmlFor="sso-alias">Identity provider name in Keycloak</label>
          <input id="sso-alias" required placeholder="northwind-entra" value={alias} onChange={(e) => setAlias(e.target.value)} />
          <small>The alias your Sentrail administrator gave the connection: letters, numbers and hyphens.</small>
        </div>
        {problem && <div className="err" role="alert">{problem}</div>}
        {setup.isError && <ErrorBox error={setup.error} />}
        <div className="actions"><button className="btn primary" disabled={setup.isPending}>{setup.isPending ? "Saving…" : "Save and get DNS record"}</button></div>
      </form>

      {setup.isSuccess && (
        <div className="panel narrow" role="status" aria-label="DNS record">
          <b>Add this TXT record to your DNS</b>
          <dl className="plain">
            <dt>Name</dt><dd className="mono" data-testid="txt-name">{setup.data.txt_record.name}</dd>
            <dt>Value</dt><dd className="mono" data-testid="txt-value" style={{ wordBreak: "break-all" }}>{setup.data.txt_record.value}</dd>
          </dl>
          <p className="muted">This record is shown now only. If you leave this page, save the setup again for a new one. DNS changes can take up to an hour.</p>
          {verify.isError && <ErrorBox error={verify.error} />}
          {verify.isSuccess && <p className="verified">Verified: {verify.data.verified} now signs in through your identity provider.</p>}
          {!verify.isSuccess && <div className="actions"><button className="btn primary" disabled={verify.isPending} onClick={() => verify.mutate()}>{verify.isPending ? "Checking…" : "Check DNS record"}</button></div>}
        </div>
      )}
    </>
  );
}
