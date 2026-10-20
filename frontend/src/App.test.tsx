import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { App } from "./App";
import { AuthProvider } from "./hooks/useAuth";
import { setAccessToken } from "./services/http";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const ME = {
  user_id: "u1", name: "Ravi K.", email: "r•••@northwindremit.ca", role: "Compliance analyst",
  tenant: { id: "o1", name: "Northwind Remit Inc.", slug: "northwind", environment: "production", brand_color: "#0F6E56" },
  permissions: ["cases.view"], features: ["alerts"],
  mfa_enabled: true, mfa_setup: null, session_mfa: true,
};

function renderAt(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <AuthProvider><App /></AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  setAccessToken(null);
});

describe("App", () => {
  it("sends a signed-out visitor to sign-in", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(401, { detail: "Sign in again" })));
    renderAt("/alerts");
    expect(await screen.findByRole("heading", { name: "Sign in to Sentrail" })).toBeInTheDocument();
  });

  it("shows the OIDC error the API redirected back with", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(401, {})));
    renderAt("/signin?error=no_account");
    expect(await screen.findByRole("alert")).toHaveTextContent("There's no Sentrail account");
  });

  it("resumes a session from the refresh cookie and shows only what the role can use", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (url.endsWith("/me")) return json(200, ME);
      if (url.includes("/alerts")) return json(200, []);
      return json(404, {});
    }));
    renderAt("/");
    expect(await screen.findByRole("heading", { name: "Alerts" })).toBeInTheDocument();
    expect(screen.getByText("Northwind Remit Inc.")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Audit log" })).not.toBeInTheDocument(); // no audit.view
    expect(screen.queryByRole("link", { name: "Wallet trace" })).not.toBeInTheDocument(); // no wallet.trace
  });

  it("blocks a screen the role can't use even when the URL is typed directly", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (url.endsWith("/me")) return json(200, ME);
      return json(403, { detail: "Your role doesn't allow this" });
    }));
    renderAt("/audit");
    expect(await screen.findByRole("heading", { name: "No access" })).toBeInTheDocument();
  });

  it("sends a user who must set up two-factor to the setup screen, with no way to skip it", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (url.endsWith("/me")) return json(200, { ...ME, mfa_enabled: false, mfa_setup: "required", session_mfa: false });
      return json(403, { detail: "Set up two-factor authentication to continue" });
    }));
    renderAt("/alerts");
    expect(await screen.findByRole("heading", { name: "Set up two-factor authentication" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Not now" })).not.toBeInTheDocument();
  });

  it("doesn't push optional two-factor: password sign-in goes straight to the app, with no prompt or banner", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.endsWith("/auth/refresh")) return json(401, {});
      if (url.endsWith("/auth/login")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600, mfa_enabled: false });
      if (url.endsWith("/me")) return json(200, { ...ME, mfa_enabled: false, mfa_setup: "optional", session_mfa: false });
      if (url.includes("/alerts")) return json(200, []);
      return json(404, {});
    }));
    renderAt("/signin");
    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "ravi.k@northwindremit.ca" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "a long enough passphrase" } });
    fireEvent.click(screen.getByRole("button", { name: /^Continue$/ }));
    expect(await screen.findByRole("heading", { name: "Alerts" })).toBeInTheDocument();
    expect(screen.queryByText(/Two-factor authentication is off/)).not.toBeInTheDocument();
  });

  it("lets a user turn on two-factor from My account and shows a QR code to scan", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (url.endsWith("/me")) return json(200, { ...ME, mfa_enabled: false, mfa_setup: "optional", session_mfa: false });
      if (url.endsWith("/me/mfa/setup") && init?.method === "POST")
        return json(200, { otpauth_uri: "otpauth://totp/Sentrail:r%40x.ca?secret=JBSWY3DPEHPK3PXP&issuer=Sentrail", secret: "JBSWY3DPEHPK3PXP" });
      if (url.includes("/me/sessions")) return json(200, []);
      return json(404, {});
    }));
    renderAt("/account");
    fireEvent.click(await screen.findByRole("link", { name: "Turn on two-factor" }));
    fireEvent.click(await screen.findByRole("button", { name: "Set up now" }));
    expect(await screen.findByRole("img", { name: /QR code/ })).toBeInTheDocument();
    expect(screen.getByLabelText(/Type this key instead/)).toHaveValue("JBSWY3DPEHPK3PXP");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(await screen.findByRole("heading", { name: "My account" })).toBeInTheDocument();
  });

  describe("sign-in failures", () => {
    const attempt = async (res: () => Response | Promise<Response>) => {
      vi.stubGlobal("fetch", vi.fn(async (url: string) => (url.endsWith("/auth/login") ? res() : json(401, {}))));
      renderAt("/signin");
      fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "someone@example.com" } });
      fireEvent.change(screen.getByLabelText("Password"), { target: { value: "not the password" } });
      fireEvent.click(screen.getByRole("button", { name: /^Continue$/ }));
      return screen.findByRole("alert");
    };
    it("says the same thing for an unknown email and a wrong password, and points to the invitation", async () => {
      expect(await attempt(() => json(401, { detail: "Email or password is incorrect" })))
        .toHaveTextContent("Email or password is incorrect. If you don't have an account yet, ask your administrator for an invitation.");
    });
    it("explains a malformed email without showing the validator's text", async () => {
      const box = await attempt(() => json(422, { detail: [{ msg: "value is not a valid email address: The part after the @-sign is not valid" }] }));
      expect(box).toHaveTextContent("Enter a valid email address and your password.");
      expect(box).not.toHaveTextContent("@-sign");
    });
    it("explains the lockout", async () => {
      expect(await attempt(() => json(429, { detail: "Too many attempts. Try again in a few minutes" }))).toHaveTextContent("Too many attempts. Wait a few minutes");
    });
    it("explains a server error", async () => {
      expect(await attempt(() => new Response("Internal Server Error", { status: 500 }))).toHaveTextContent("Something went wrong on our side");
    });
    it("explains an unreachable API", async () => {
      expect(await attempt(() => { throw new TypeError("Failed to fetch"); })).toHaveTextContent("can't be reached");
    });
  });
});
