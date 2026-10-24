import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { AuthProvider } from "../hooks/useAuth";
import { setAccessToken } from "../services/http";
import ROLES from "../test/roles.fixture.json";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

type RoleName = keyof typeof ROLES;
const FEATURES = ["alerts", "trace", "screening", "ai", "statements", "export", "scim", "audit_streaming"];

/** /me for a built-in role, with the permissions the role templates (backend catalogue) give it. */
const meFor = (role: RoleName, extra: Record<string, unknown> = {}) => {
  const platform = ROLES[role].scope === "platform";
  return {
    user_id: "me", name: "Test Person", email: "t•••@example.com", role,
    tenant: platform
      ? { name: "Platform console", slug: "platform", environment: "platform", brand_color: "#534AB7" }
      : { id: "o1", name: "Northwind Remit Inc.", slug: "northwind", environment: "production", brand_color: "#0F6E56" },
    permissions: ROLES[role].permissions, features: platform ? [] : FEATURES, mfa_enabled: true, mfa_setup: null, session_mfa: true,
    scope: platform ? "platform" : "tenant", ...extra,
  };
};

interface Call { url: string; method: string; body: unknown }

function stubApi(me: unknown, extra: Record<string, (c: Call) => Response> = {}) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const call = { url, method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : undefined };
    if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
    if (url.endsWith("/me")) return json(200, me);
    calls.push(call);
    const key = `${call.method} ${new URL(url).pathname}`;
    if (extra[key]) return extra[key](call);
    return json(404, { detail: "not stubbed" });
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

const navLinks = () => within(screen.getByRole("navigation", { name: "Main" })).getAllByRole("link").map((a) => a.textContent).filter((t) => t !== "My account").sort();

// What each built-in role sees in the navigation. Written out by hand: the permissions come from the catalogue, the screens from the app.
const NAV: Record<string, string[]> = {
  "Tenant admin": ["Access reviews", "Alerts", "API keys", "Audit log", "Company sign-in", "Features", "Platform access requests", "Roles", "Screening policy",
                   "Search", "Security settings", "Users", "Wallet trace"],
  "Compliance officer": ["Alerts", "Audit log", "Screening policy", "Search", "Wallet trace"],
  "Compliance analyst": ["Alerts", "Screening policy", "Search", "Wallet trace"],
  "Auditor (read-only)": ["Alerts", "Audit log", "Screening policy", "Search"],
  "Platform owner": ["Approvals", "Audit log", "Organizations", "Plans", "Security baseline", "Staff", "Staff access review", "Tenant access sessions"],
  "Platform support": ["Organizations"],
  "Platform auditor": ["Audit log", "Tenant access sessions"],
};

describe("what each role sees", () => {
  for (const [role, links] of Object.entries(NAV)) {
    it(`${role}: the navigation shows exactly what the role can use`, async () => {
      stubApi(meFor(role as RoleName));
      renderAt("/account");
      await screen.findByRole("heading", { name: /My account|Account/i });
      expect(navLinks()).toEqual([...links].sort());
    });
  }

  // The screens a role isn't given answer "No access" even when the address is typed in (and the API refuses the calls on its own: backend roles_e2e).
  const BLOCKED: [RoleName, string[]][] = [
    ["Compliance analyst", ["/users", "/roles", "/security", "/access-reviews", "/audit", "/api-keys", "/organizations", "/staff"]],
    ["Compliance officer", ["/users", "/roles", "/security", "/access-reviews", "/organizations"]],
    ["Auditor (read-only)", ["/users", "/security", "/access-reviews", "/staff", "/approvals"]],
    ["Platform support", ["/staff", "/approvals", "/platform-security", "/access-sessions", "/audit", "/alerts", "/users"]],
    ["Platform auditor", ["/organizations", "/staff", "/approvals", "/alerts", "/users", "/security"]],
    ["Tenant admin", ["/organizations", "/staff", "/approvals", "/platform-security", "/access-sessions"]],
  ];
  for (const [role, paths] of BLOCKED) {
    for (const path of paths) {
      it(`${role} is told "No access" at ${path}`, async () => {
        stubApi(meFor(role));
        renderAt(path);
        expect(await screen.findByRole("heading", { name: "No access" })).toBeInTheDocument();
      });
    }
  }
});

describe("preview as role", () => {
  it("shows a Tenant admin only what the chosen role sees, and exits cleanly", async () => {
    const analyst = ROLES["Compliance analyst"].permissions.map((key) => ({ key, group: "x", description: key, step_up: false }));
    stubApi(meFor("Tenant admin"), {
      "GET /admin/roles": () => json(200, { roles: [{ id: "r1", name: "Compliance analyst", system: true, perms: ROLES["Compliance analyst"].permissions }], warnings: [] }),
      "GET /admin/roles/r1/effective": () => json(200, { role: "Compliance analyst", locked: false, permissions: analyst, features: FEATURES, warnings: [] }),
    });
    renderAt("/roles");
    fireEvent.click(await screen.findByRole("button", { name: "Preview as Compliance analyst" }));
    expect(await screen.findByText(/Previewing as Compliance analyst/)).toBeInTheDocument();
    await waitFor(() => expect(navLinks()).toEqual([...NAV["Compliance analyst"]].sort()));
    expect(screen.getByText(/server still applies your own permissions/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Exit preview" }));
    await waitFor(() => expect(navLinks()).toEqual([...NAV["Tenant admin"]].sort()));
  });

  it("shows the separation-of-duties warnings after saving a role", async () => {
    stubApi(meFor("Tenant admin"), {
      "GET /admin/roles": () => json(200, { roles: [{ id: "r9", name: "Drafter", system: false, perms: ["str.draft"] }], warnings: [] }),
      "PUT /admin/roles/r9": () => json(200, { ok: true, warnings: ["Drafter can both draft and approve. One person could write a report and approve it."] }),
      "GET /admin/roles/r9/effective": () => json(200, { role: "Drafter", locked: false, permissions: [], features: [], warnings: [] }),
    });
    renderAt("/roles");
    const form = await screen.findByRole("form", { name: "Role Drafter" });
    fireEvent.click(within(form).getByLabelText(/Approve and file STRs/));
    fireEvent.click(within(form).getByRole("button", { name: "Save role" }));
    expect(await screen.findByText(/One person could write a report and approve it/)).toBeInTheDocument();
  });
});

describe("effective permissions", () => {
  it("lists what a person can do, and which actions ask for a second factor", async () => {
    stubApi(meFor("Tenant admin"), {
      "GET /admin/users": () => json(200, [{ id: "me", name: "Test Person", email: "t•••@example.com", role: "Tenant admin", status: "active", mfa: true, last_login: null },
                                           { id: "u2", name: "Ravi K.", email: "r•••@example.com", role: "Compliance officer", status: "active", mfa: true, last_login: null }]),
      "GET /admin/roles": () => json(200, { roles: [], warnings: [] }),
      "GET /admin/users/u2/effective-permissions": () => json(200, { role: "Compliance officer", locked: false, features: ["alerts"], warnings: [],
        permissions: [{ key: "str.approve", group: "Reporting", description: "Approve and file an STR", step_up: true }, { key: "cases.view", group: "Customer data", description: "Alert queue", step_up: false }] }),
    });
    renderAt("/users");
    const row = (await screen.findByText("Ravi K.", { selector: "td" })).closest("tr")!;
    expect(within((await screen.findByText("Test Person", { selector: "td" })).closest("tr")!).queryByRole("button", { name: "Permissions" })).not.toBeInTheDocument();
    fireEvent.click(within(row).getByRole("button", { name: "Permissions" }));
    expect(await screen.findByText(/Approve and file an STR/)).toBeInTheDocument();
    expect(screen.getByText(/asks for a fresh second factor/)).toBeInTheDocument();
  });
});

describe("access reviews", () => {
  const detail = (decision: string | null) => ({
    id: "rv1", title: "Q4 review", status: "open", opened_at: "2026-10-01T00:00:00Z", due_at: "2026-10-31T00:00:00Z", signed_off_at: null, signed_off_by: null, overdue: false,
    members: [{ user_id: "u2", name: "Ravi K.", email: "r•••@example.com", role: "Compliance analyst", decision, new_role_id: null, note: null, decided_at: null }],
  });

  it("opens a review, records a decision and signs off", async () => {
    let decided: string | null = null;
    const calls = stubApi(meFor("Tenant admin"), {
      "GET /admin/access-reviews": () => json(200, []),
      "POST /admin/access-reviews": () => json(200, { id: "rv1", items: 1 }),
      "GET /admin/access-reviews/rv1": () => json(200, detail(decided)),
      "GET /admin/roles": () => json(200, { roles: [{ id: "r-off", name: "Compliance officer", system: true, perms: [] }], warnings: [] }),
      "PUT /admin/access-reviews/rv1/members/u2": (c) => { decided = (c.body as { decision: string }).decision; return json(200, { decision: decided }); },
      "POST /admin/access-reviews/rv1/sign-off": () => json(200, { status: "signed_off", keep: 0, change: 0, remove: 1 }),
    });
    renderAt("/access-reviews");
    fireEvent.click(await screen.findByRole("button", { name: "Open a review" }));
    const row = (await screen.findByText("Ravi K.", { selector: "td" })).closest("tr")!;
    expect(screen.getByRole("button", { name: "Sign off and apply decisions" })).toBeDisabled();
    fireEvent.click(within(row).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Sign off and apply decisions" })).toBeEnabled());
    expect(calls.find((c) => c.method === "PUT")!.body).toEqual({ decision: "remove" });
    fireEvent.click(screen.getByRole("button", { name: "Sign off and apply decisions" }));
    expect(await screen.findByText(/Signed off. Kept 0, changed 0, removed 1/)).toBeInTheDocument();
  });

  it("shows the server's refusal when a decision isn't allowed", async () => {
    stubApi(meFor("Tenant admin"), {
      "GET /admin/access-reviews": () => json(200, [{ id: "rv1", title: "Q4 review", status: "open", opened_at: "2026-10-01T00:00:00Z", due_at: "2026-10-31T00:00:00Z", signed_off_at: null, signed_off_by: null, overdue: false, items: 1, decided: 0 }]),
      "GET /admin/access-reviews/rv1": () => json(200, detail(null)),
      "GET /admin/roles": () => json(200, { roles: [], warnings: [] }),
      "PUT /admin/access-reviews/rv1/members/u2": () => json(409, { detail: "Your organization needs at least one active admin" }),
    });
    renderAt("/access-reviews");
    fireEvent.click(await screen.findByRole("button", { name: "Open" }));
    const row = (await screen.findByText("Ravi K.", { selector: "td" })).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Remove" }));
    expect(await screen.findByText(/at least one active admin/)).toBeInTheDocument();
  });
});

describe("platform owner access requests (the organization's side)", () => {
  const req = (status: string) => ({ id: "s1", tenant_id: "o1", tenant: "Northwind", owner_user_id: "o9", reason: "Investigating ticket 4411", status,
                                       requested_at: "2026-10-23T10:00:00Z", started_at: null, expires_at: status === "active" ? "2026-10-23T11:00:00Z" : null, extended: false,
                                       ended_at: null, ended_reason: null, legal_hold: false, request_expires_at: "2026-10-24T10:00:00Z" });
  it("approves a request, and a denial needs a reason", async () => {
    const calls = stubApi(meFor("Tenant admin"), {
      "GET /admin/access-requests": () => json(200, [req("requested")]),
      "POST /admin/access-requests/s1/approve": () => json(200, { status: "active" }),
      "POST /admin/access-requests/s1/deny": () => json(200, { status: "denied" }),
    });
    renderAt("/owner-access");
    expect(await screen.findByText("Investigating ticket 4411")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    expect(screen.getByRole("button", { name: "Deny" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Reason for denying"), { target: { value: "Not during the audit" } });
    fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/deny"))!.body).toEqual({ reason: "Not during the audit" }));
  });

  it("lets the organization end a live session", async () => {
    const calls = stubApi(meFor("Tenant admin"), {
      "GET /admin/access-requests": () => json(200, [req("active")]),
      "DELETE /admin/access-requests/s1": () => json(200, { ended: "s1" }),
    });
    renderAt("/owner-access");
    fireEvent.click(await screen.findByRole("button", { name: "End access now" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true));
  });
});

describe("teams", () => {
  it("is hidden while the flag is off, and shown to a team admin when it is on", async () => {
    stubApi(meFor("Tenant admin", { teams_enabled: false }));
    const first = renderAt("/account");
    await screen.findByRole("heading", { name: /Account/i });
    expect(screen.queryByRole("link", { name: "Teams" })).not.toBeInTheDocument();
    first.unmount();
    stubApi(meFor("Compliance officer", { teams_enabled: true }));
    renderAt("/account");
    expect(await screen.findByRole("link", { name: "Teams" })).toBeInTheDocument();
  });

  it("creates a team and sets its members", async () => {
    const calls = stubApi(meFor("Tenant admin", { teams_enabled: true }), {
      "GET /admin/teams": () => json(200, [{ id: "t1", name: "Night shift", members: 0, open_alerts: 0 }]),
      "POST /admin/teams": () => json(200, { id: "t2" }),
      "GET /admin/teams/t1": () => json(200, { id: "t1", name: "Night shift", members: [] }),
      "GET /admin/users": () => json(200, [{ id: "u2", name: "Ravi K.", email: "r•••@example.com", role: "Compliance analyst", status: "active", mfa: false, last_login: null }]),
      "PUT /admin/teams/t1/members": () => json(200, { members: 1 }),
    });
    renderAt("/teams");
    fireEvent.change(await screen.findByLabelText("New team"), { target: { value: "Day shift" } });
    fireEvent.click(screen.getByRole("button", { name: "Create team" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")!.body).toEqual({ name: "Day shift" }));
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    fireEvent.click(await screen.findByLabelText(/Ravi K./));
    fireEvent.click(screen.getByRole("button", { name: "Save members" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")!.body).toEqual({ user_ids: ["u2"] }));
  });

  it("offers my team queues on the alert list", async () => {
    const calls = stubApi(meFor("Compliance analyst", { teams_enabled: true }), {
      "GET /me/teams": () => json(200, { teams: [{ id: "t1", name: "Night shift", open_alerts: 3 }] }),
      "GET /alerts": () => json(200, []),
    });
    renderAt("/alerts");
    fireEvent.click(await screen.findByRole("button", { name: "Night shift (3)" }));
    await waitFor(() => expect(calls.some((c) => c.url.includes("team=t1"))).toBe(true));
  });
});

describe("platform approvals", () => {
  const item = (by: string) => ({ id: "a1", action: "tenant.delete", payload: { name: "Acme Remit" }, requested_by: by, approved_by: null, status: "pending",
                                   reason: "contract ended", created_at: "2026-10-23T10:00:00Z", decided_at: null, expires_at: "2026-10-24T10:00:00Z" });
  it("lets a second owner approve, but not the owner who asked", async () => {
    const calls = stubApi(meFor("Platform owner"), {
      "GET /platform/approvals": () => json(200, [item("someone-else")]),
      "POST /platform/approvals/a1/approve": () => json(200, { status: "approved" }),
    });
    const first = renderAt("/approvals");
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/a1/approve"))).toBe(true));
    first.unmount();
    stubApi(meFor("Platform owner"), { "GET /platform/approvals": () => json(200, [item("me")]) });
    renderAt("/approvals");
    expect(await screen.findByText("Waiting for a second owner")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
  });
});

describe("exports", () => {
  it("asks for the signed audit export and fetches it once through the link", async () => {
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: () => "blob:x", revokeObjectURL: () => undefined }));
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    const calls = stubApi(meFor("Auditor (read-only)"), {
      "GET /admin/audit": () => json(200, []),
      "POST /admin/audit/export": () => json(200, { download_path: "/me/exports/tok", expires_at: "2026-10-23T11:00:00Z", filename: "audit-1.json", note: "" }),
      "GET /me/exports/tok": () => new Response("{}", { status: 200 }),
    });
    renderAt("/audit");
    fireEvent.click(await screen.findByRole("button", { name: "Export signed JSON" }));
    expect(await screen.findByText(/Downloaded audit-1.json/)).toBeInTheDocument();
    expect(calls.filter((c) => c.url.includes("/me/exports/tok"))).toHaveLength(1);
  });

  it("hides the export buttons from someone without audit.export", async () => {
    stubApi(meFor("Compliance officer"), { "GET /admin/audit": () => json(200, []) });
    renderAt("/audit");
    await screen.findByRole("button", { name: "Verify chain" });
    expect(screen.queryByRole("button", { name: "Export signed JSON" })).not.toBeInTheDocument();
  });
});

describe("who may enter the organization", () => {
  it("lets a Tenant admin choose how Sentrail platform owners get in, and sends only that change", async () => {
    const calls = stubApi(meFor("Tenant admin"), {
      "GET /admin/security": () => json(200, {
        mfa_required: false, sso_enabled: false, idle_timeout_min: 15, min_password_len: 14, ip_allowlist: [], retention_years: 7,
        dormant_days: 90, access_review_days: 90, export_limit_per_hour: 20, anomaly_searches_per_hour: 100, anomaly_exports_per_hour: 10,
        alert_new_country: true, owner_access: "allow", legal_hold: false, encryption: { algorithm: "AES-256-GCM", current_key: "v1", key_manager: "local" },
      }),
      "PUT /admin/security": () => json(200, { ok: true }),
    });
    renderAt("/security");
    fireEvent.change(await screen.findByLabelText(/Sentrail platform owner asks to enter/), { target: { value: "require_approval" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")!.body).toEqual({ owner_access: "require_approval" }));
  });
});
