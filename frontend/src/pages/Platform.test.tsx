import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { AuthProvider } from "../hooks/useAuth";
import { setAccessToken } from "../services/http";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const platformMe = (permissions: string[]) => ({
  user_id: "p1", name: "Pat Platform", email: "p•••@sentrail.io", role: "Platform admin",
  tenant: { name: "Sentrail", slug: "platform", environment: "platform", brand_color: "#0F6E56" },
  permissions, features: [], mfa_enabled: true, mfa_setup: null, session_mfa: true,
});

const PLANS = [
  { key: "starter", name: "Starter", features: ["screening", "alerts"], max_users: 5, organizations: 3 },
  { key: "professional", name: "Professional", features: ["screening", "alerts", "ai"], max_users: 25, organizations: 1 },
];
const ORG = {
  id: "o1", legal_name: "Northwind Remit Inc.", business_type: "MSB", registration: "M1", data_region: "ca-central",
  plan: "starter", status: "active", users: 4, features: null,
};

interface Call { method: string; body: unknown }

function stubApi(me: unknown, routes: Record<string, () => Response>) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const path = new URL(url).pathname;
    if (path === "/auth/refresh") return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
    if (path === "/me") return json(200, me);
    const method = init?.method ?? "GET";
    calls.push({ method, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    return routes[`${method} ${path}`]?.() ?? json(404, { detail: "not stubbed" });
  }));
  return calls;
}

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

describe("Plans", () => {
  it("applies a plan change only after a confirmation that says what switches off", async () => {
    const calls = stubApi(platformMe(["platform.plans.manage"]), {
      "GET /platform/plans": () => json(200, PLANS),
      "PUT /platform/plans/starter": () => json(200, { ok: true }),
    });
    renderAt("/plans");
    const card = await screen.findByRole("region", { name: "Plan Starter" });
    fireEvent.click(within(card).getByRole("checkbox", { name: "Alert queue" })); // remove
    fireEvent.click(within(card).getByRole("checkbox", { name: "Wallet trace" })); // add
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
    fireEvent.click(within(card).getByRole("button", { name: "Review change" }));
    expect(within(card).getByRole("alert")).toHaveTextContent("changes 3 organizations immediately");
    expect(within(card).getByRole("alert")).toHaveTextContent("Alert queue will switch off");
    fireEvent.click(within(card).getByRole("button", { name: "Apply to all" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    expect(calls.find((c) => c.method === "PUT")!.body).toEqual({ features: ["screening", "trace"] });
  });

  it("is read-only for staff who can't manage plans", async () => {
    stubApi(platformMe(["orgs.manage"]), { "GET /platform/plans": () => json(200, PLANS) });
    renderAt("/plans");
    const card = await screen.findByRole("region", { name: "Plan Starter" });
    expect(within(card).getByRole("checkbox", { name: "Alert queue" })).toBeDisabled();
    expect(screen.getByText(/can view plans but not change them/)).toBeInTheDocument();
  });

  it("shows the API's refusal", async () => {
    stubApi(platformMe(["platform.plans.manage"]), {
      "GET /platform/plans": () => json(200, PLANS),
      "PUT /platform/plans/starter": () => json(400, { detail: "Unknown feature" }),
    });
    renderAt("/plans");
    const card = await screen.findByRole("region", { name: "Plan Starter" });
    fireEvent.click(within(card).getByRole("checkbox", { name: "Wallet trace" }));
    fireEvent.click(within(card).getByRole("button", { name: "Review change" }));
    fireEvent.click(within(card).getByRole("button", { name: "Apply to all" }));
    await waitFor(() => expect(within(card).getAllByRole("alert").some((a) => a.textContent?.includes("Unknown feature"))).toBe(true));
  });
});

describe("Organizations: plan", () => {
  it("moves an organization to another plan only after confirming", async () => {
    const calls = stubApi(platformMe(["orgs.manage"]), {
      "GET /platform/orgs": () => json(200, [ORG]),
      "PUT /platform/orgs/o1/plan": () => json(200, { ok: true }),
    });
    renderAt("/organizations");
    fireEvent.change(await screen.findByLabelText("Plan for Northwind Remit Inc."), { target: { value: "professional" } });
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
    expect(screen.getByRole("alert")).toHaveTextContent("Move Northwind Remit Inc. from starter to professional?");
    fireEvent.click(screen.getByRole("button", { name: "Move organization" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    expect(calls.find((c) => c.method === "PUT")!.body).toEqual({ plan: "professional" });
  });

  it("shows plain text, not a selector, to staff who can't move organizations", async () => {
    stubApi(platformMe(["platform.support"]), { "GET /platform/orgs": () => json(200, [ORG]) });
    renderAt("/organizations");
    await screen.findByText("Northwind Remit Inc.", { selector: "td" });
    expect(screen.queryByLabelText("Plan for Northwind Remit Inc.")).not.toBeInTheDocument();
    expect(screen.getByText("starter")).toBeInTheDocument();
  });
});

describe("Platform security baseline", () => {
  const BASE = {
    min_password_len_floor: 14, max_idle_timeout_min: 30, max_session_hours: 8, retention_years_floor: 5,
    passkeys_allowed: false, platform_staff_passkey_only: false, allowed_regions: ["ca-central", "eu-west"],
    mfa: "Always required for platform staff and organization admins.",
  };

  it("sends the whole object after a confirmation, keeping the values it doesn't edit", async () => {
    let current = BASE;
    const calls = stubApi(platformMe(["platform.security.manage"]), {
      "GET /platform/security": () => json(200, current),
      "PUT /platform/security": () => json(200, { ok: true, tenants_checked: 6 }),
    });
    renderAt("/platform-security");
    const review = await screen.findByRole("button", { name: "Review change" });
    expect(review).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Shortest allowed password/), { target: { value: "16" } });
    fireEvent.click(review);
    expect(screen.getByRole("alert")).toHaveTextContent("applies to every organization now");
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
    current = { ...BASE, min_password_len_floor: 16 }; // what the API returns after the save
    fireEvent.click(screen.getByRole("button", { name: "Apply to all organizations" }));
    await screen.findByText(/6 organizations checked/);
    // a partial body would reset max_session_hours, passkeys and regions to the API's defaults
    expect(calls.find((c) => c.method === "PUT")!.body).toEqual({
      min_password_len_floor: 16, max_idle_timeout_min: 30, retention_years_floor: 5,
      max_session_hours: 8, passkeys_allowed: false, platform_staff_passkey_only: false, allowed_regions: ["ca-central", "eu-west"],
    });
  });

  it("is hidden from staff without the permission and shows the API's refusal", async () => {
    stubApi(platformMe(["platform.plans.manage"]), {});
    const first = renderAt("/platform-security");
    expect(await screen.findByRole("heading", { name: "No access" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Security baseline" })).not.toBeInTheDocument();
    first.unmount();

    stubApi(platformMe(["platform.security.manage"]), {
      "GET /platform/security": () => json(200, BASE),
      "PUT /platform/security": () => json(422, { detail: "Retention can't be below 5 years" }),
    });
    renderAt("/platform-security");
    fireEvent.change(await screen.findByLabelText(/Shortest audit retention/), { target: { value: "6" } });
    fireEvent.click(screen.getByRole("button", { name: "Review change" }));
    fireEvent.click(screen.getByRole("button", { name: "Apply to all organizations" }));
    await waitFor(() => expect(screen.getAllByRole("alert").some((a) => a.textContent?.includes("Retention can't be below 5 years"))).toBe(true));
  });
});
