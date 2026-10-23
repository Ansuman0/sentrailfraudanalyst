import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { AuthProvider } from "../hooks/useAuth";
import { setAccessToken } from "../services/http";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const TENANT_A = { id: "ta", name: "Alpha Remit", slug: "alpha", environment: "production", brand_color: "#0F6E56" };
const CHOICES = [
  { id: "ta", name: "Alpha Remit", slug: "alpha", role: "Compliance officer", kind: "tenant", current: false },
  { id: "tb", name: "Beta Digital", slug: "beta", role: "Auditor (read-only)", kind: "tenant", current: false },
];
const SELECTING = {
  user_id: "u1", name: "Multi", email: "m•••@x.example", role: null, tenant: null, permissions: [], features: [],
  mfa_enabled: true, mfa_setup: null, session_mfa: false, scope: "select", selecting: true, tenants: CHOICES,
};
const IN_ALPHA = {
  user_id: "u1", name: "Multi", email: "m•••@x.example", role: "Compliance officer", tenant: TENANT_A, permissions: ["cases.view"],
  features: ["alerts"], mfa_enabled: true, mfa_setup: null, session_mfa: true, scope: "tenant", selecting: false,
  tenants: CHOICES.map((c) => ({ ...c, current: c.id === "ta" })),
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

describe("tenant routing after sign-in", () => {
  it("sends a signed-in person with several memberships to the picker, and into the chosen tenant", async () => {
    let chosen = false;
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (url.endsWith("/session/tenant")) {
        expect(JSON.parse(String(init?.body))).toEqual({ tenant_id: "tb" });
        chosen = true;
        return json(200, { access_token: "t2", token_type: "Bearer", expires_in: 600 });
      }
      if (url.endsWith("/me")) return json(200, chosen ? { ...IN_ALPHA, tenant: { ...TENANT_A, id: "tb", name: "Beta Digital" }, role: "Auditor (read-only)" } : SELECTING);
      if (url.includes("/alerts")) return json(200, []);
      return json(404, {});
    }));
    renderAt("/alerts");
    expect(await screen.findByRole("heading", { name: "Choose where to work" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Alpha Remit/ })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Beta Digital/ }));
    expect(await screen.findByRole("heading", { name: "Alerts" })).toBeInTheDocument();
    expect(screen.getByLabelText("Current organization")).toHaveTextContent("Beta Digital");
  });

  it("shows the no-access page when there is nowhere to go", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (url.endsWith("/me")) return json(200, { ...SELECTING, tenants: [] });
      return json(404, {});
    }));
    renderAt("/alerts");
    expect(await screen.findByRole("heading", { name: "No access yet" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument();
  });

  it("shows a switcher only to people with more than one place to work, and switches through the API", async () => {
    let switched: unknown = null;
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (url.endsWith("/session/tenant")) {
        switched = JSON.parse(String(init?.body));
        return json(200, { access_token: "t2", token_type: "Bearer", expires_in: 600 });
      }
      if (url.endsWith("/me")) return json(200, IN_ALPHA);
      if (url.includes("/alerts")) return json(200, []);
      return json(404, {});
    }));
    renderAt("/alerts");
    const select = await screen.findByLabelText("Switch tenant");
    expect(select).toHaveValue("ta");
    fireEvent.change(select, { target: { value: "tb" } });
    await waitFor(() => expect(switched).toEqual({ tenant_id: "tb" }));
  });

  it("hides the switcher when there is only one place", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (url.endsWith("/me")) return json(200, { ...IN_ALPHA, tenants: [] });
      if (url.includes("/alerts")) return json(200, []);
      return json(404, {});
    }));
    renderAt("/alerts");
    expect(await screen.findByRole("heading", { name: "Alerts" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Switch tenant")).not.toBeInTheDocument();
  });
});

describe("step-up dialog", () => {
  it("prompts for a code when the API asks, then repeats the action", async () => {
    let policyCalls = 0;
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (url.endsWith("/me")) return json(200, { ...IN_ALPHA, tenants: [], permissions: ["cases.view", "policy.edit"] });
      if (url.endsWith("/session/step-up")) {
        expect(JSON.parse(String(init?.body))).toEqual({ code: "123456" });
        return json(200, { access_token: "fresh", token_type: "Bearer", expires_in: 600 });
      }
      if (url.endsWith("/policy") && (init?.method ?? "GET") === "GET") {
        policyCalls += 1;
        const auth = (init?.headers as Record<string, string>)["Authorization"];
        return auth === "Bearer fresh" ? json(200, { hold_at: 40, block_at: 75, travel_rule_threshold: 1000, self_hosted_proof_above: 1000, always_block_sanctions: true })
                                         : json(401, { error: "step_up_required" });
      }
      return json(404, {});
    }));
    renderAt("/policy");
    expect(await screen.findByRole("dialog", { name: "Confirm it's you" })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(policyCalls).toBe(2);
  });

  it("closes without retrying when cancelled", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (url.endsWith("/me")) return json(200, { ...IN_ALPHA, tenants: [] });
      if (url.endsWith("/policy")) return json(401, { error: "step_up_required" });
      return json(404, {});
    }));
    renderAt("/policy");
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });
});

describe("owner access banner", () => {
  it("shows a persistent banner while a platform owner works inside a tenant, and ends access from it", async () => {
    let ended = false;
    let switched: unknown = null;
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (url.endsWith("/me/access-session")) { ended = true; return json(200, { ended: "s1" }); }
      if (url.endsWith("/session/tenant")) { switched = JSON.parse(String(init?.body)); return json(200, { access_token: "t2", token_type: "Bearer", expires_in: 600 }); }
      if (url.endsWith("/me")) {
        return json(200, { ...IN_ALPHA, tenants: [], role: "Tenant admin",
          access_session: ended ? null : { id: "s1", expires_at: new Date(Date.now() + 3600_000).toISOString(), reason: "ticket 501", extended: false } });
      }
      if (url.includes("/alerts")) return json(200, []);
      return json(404, {});
    }));
    renderAt("/alerts");
    const banner = (await screen.findByText(/Platform owner access/)).closest(".accessbanner") as HTMLElement;
    expect(banner).toHaveTextContent("Alpha Remit");
    expect(banner).toHaveTextContent("ticket 501");
    fireEvent.click(screen.getByRole("button", { name: "End access" }));
    await waitFor(() => expect(ended).toBe(true));
    await waitFor(() => expect(switched).toEqual({ tenant_id: null }));
  });

  it("shows no banner for ordinary members", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (url.endsWith("/me")) return json(200, { ...IN_ALPHA, tenants: [], access_session: null });
      if (url.includes("/alerts")) return json(200, []);
      return json(404, {});
    }));
    renderAt("/alerts");
    expect(await screen.findByRole("heading", { name: "Alerts" })).toBeInTheDocument();
    expect(screen.queryByText(/Platform owner access/)).not.toBeInTheDocument();
  });
});
