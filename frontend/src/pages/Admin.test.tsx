import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { AuthProvider } from "../hooks/useAuth";
import { setAccessToken } from "../services/http";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const meWith = (permissions: string[], features = ["screening"]) => ({
  user_id: "me", name: "Asha Admin", email: "a•••@northwindremit.ca", role: "Organization admin",
  tenant: { id: "o1", name: "Northwind Remit Inc.", slug: "northwind", environment: "production", brand_color: "#0F6E56" },
  // a user admin holds the split-out permissions too (migration 009 grants them to whoever held users.manage)
  permissions: permissions.includes("users.manage") ? [...permissions, "users.pii.reveal", "security.manage", "apikeys.manage"] : permissions,
  features, mfa_enabled: true, mfa_setup: null, session_mfa: true,
});

const ROLES = { roles: [{ id: "r-admin", name: "Organization admin", system: true, perms: ["users.manage"] },
                        { id: "r-analyst", name: "Compliance analyst", system: true, perms: ["cases.view"] }], warnings: [] };
const USERS = [
  { id: "me", name: "Asha Admin", email: "a•••@northwindremit.ca", role: "Organization admin", status: "active", mfa: true, last_login: null },
  { id: "u2", name: "Ravi K.", email: "r•••@northwindremit.ca", role: "Compliance analyst", status: "active", mfa: false, last_login: null },
];

interface Call { url: string; method: string; body: unknown }

/** Stubs the API; returns the list of calls made after sign-in so tests can assert on what was sent. */
function stubApi(me: unknown, extra: Record<string, (c: Call) => Response> = {}) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const call = { url, method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : undefined };
    if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
    if (url.endsWith("/me")) return json(200, me);
    calls.push(call);
    const key = `${call.method} ${new URL(url).pathname}`;
    if (extra[key]) return extra[key](call);
    if (key === "GET /admin/users") return json(200, USERS);
    if (key === "GET /admin/roles") return json(200, ROLES);
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

describe("admin navigation", () => {
  it("shows the Administer links to a user admin only", async () => {
    stubApi(meWith(["users.manage"]));
    renderAt("/users");
    expect(await screen.findByRole("heading", { name: "Users" })).toBeInTheDocument();
    for (const name of ["Users", "API keys", "Security settings"]) expect(screen.getByRole("link", { name })).toBeInTheDocument();
  });

  it("hides API keys when the plan has no screening, and blocks the page for a role without users.manage", async () => {
    stubApi(meWith(["users.manage"], []));
    const first = renderAt("/users");
    await screen.findByRole("heading", { name: "Users" });
    expect(screen.queryByRole("link", { name: "API keys" })).not.toBeInTheDocument();
    first.unmount();

    stubApi(meWith(["cases.view"]));
    renderAt("/users");
    expect(await screen.findByRole("heading", { name: "No access" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Users" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
  });
});

describe("Users", () => {
  it("invites with the chosen role and offers no controls on your own row", async () => {
    const calls = stubApi(meWith(["users.manage", "roles.manage"]), {
      "POST /admin/invitations": () => json(200, { invited: "n•••@example.com" }),
    });
    renderAt("/users");
    const own = (await screen.findByText("Asha Admin", { selector: "td" })).closest("tr")!;
    expect(within(own).queryByRole("button")).not.toBeInTheDocument();
    expect(within(own).queryByRole("combobox")).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Work email"), { target: { value: "new@example.com" } });
    await waitFor(() => expect(screen.getByLabelText("Role")).not.toBeDisabled());
    fireEvent.change(screen.getByLabelText("Role"), { target: { value: "r-analyst" } });
    fireEvent.click(screen.getByRole("button", { name: "Send invitation" }));
    await screen.findByText(/Invitation sent to n•••@example.com/);
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ email: "new@example.com", role_id: "r-analyst" });
  });

  it("suspends another user and changes a role by id", async () => {
    const calls = stubApi(meWith(["users.manage", "roles.manage"]), { "PATCH /admin/users/u2": () => json(200, { ok: true }) });
    renderAt("/users");
    const row = (await screen.findByText("Ravi K.", { selector: "td" })).closest("tr")!;
    await waitFor(() => expect(within(row).getByRole("combobox")).toBeInTheDocument());
    fireEvent.change(within(row).getByRole("combobox"), { target: { value: "r-admin" } });
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    fireEvent.click(within(row).getByRole("button", { name: "Suspend" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(2));
    const patches = calls.filter((c) => c.method === "PATCH").map((c) => c.body);
    expect(patches).toEqual([{ role_id: "r-admin" }, { status: "suspended" }]);
  });

  it("shows the API's reason when a change is refused", async () => {
    stubApi(meWith(["users.manage", "roles.manage"]), {
      "PATCH /admin/users/u2": () => json(409, { detail: "At least one active Organization admin must remain" }),
    });
    renderAt("/users");
    const row = (await screen.findByText("Ravi K.", { selector: "td" })).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Suspend" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("At least one active Organization admin must remain");
  });

  it("explains why inviting is unavailable without the roles permission", async () => {
    stubApi(meWith(["users.manage"]), { "GET /admin/roles": () => json(403, { detail: "Your role can't do this" }) });
    renderAt("/users");
    expect(await screen.findByText(/needs “manage roles”/)).toBeInTheDocument();
    expect(screen.getByLabelText("Role")).toBeDisabled();
  });
});

describe("API keys", () => {
  const KEYS = [{ prefix: "sk_live_abc12345", label: "Payments", created_at: "2026-10-01T10:00:00Z", revoked_at: null, active: true }];

  it("shows a new key once, then never again", async () => {
    stubApi(meWith(["users.manage"]), {
      "GET /admin/api-keys": () => json(200, KEYS),
      "POST /admin/api-keys": () => json(200, { api_key: "sk_live_abc12345_SECRETVALUE", prefix: "sk_live_abc12345", message: "x" }),
    });
    renderAt("/api-keys");
    await screen.findByText("Payments");
    fireEvent.click(screen.getByRole("button", { name: "Create key" }));
    expect(await screen.findByTestId("new-key")).toHaveTextContent("sk_live_abc12345_SECRETVALUE");
    fireEvent.click(screen.getByRole("button", { name: "I've copied it" }));
    await waitFor(() => expect(screen.queryByTestId("new-key")).not.toBeInTheDocument());
    expect(document.body.textContent).not.toContain("SECRETVALUE");
  });

  it("asks for confirmation before revoking", async () => {
    const calls = stubApi(meWith(["users.manage"]), {
      "GET /admin/api-keys": () => json(200, KEYS),
      "DELETE /admin/api-keys/sk_live_abc12345": () => json(200, { revoked: "sk_live_abc12345" }),
    });
    renderAt("/api-keys");
    fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Yes, revoke it" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true));
  });
});

describe("Security settings", () => {
  const SETTINGS = {
    mfa_required: false, sso_enabled: false, idle_timeout_min: 15, min_password_len: 14, ip_allowlist: [], retention_years: 7, dormant_days: 90, access_review_days: 90, export_limit_per_hour: 20, anomaly_searches_per_hour: 100, anomaly_exports_per_hour: 10, alert_new_country: true,
    encryption: { algorithm: "AES-256-GCM", current_key: "v1", key_manager: "local (dev only)" },
  };

  it("sends only the two-factor switch when saving", async () => {
    let current = SETTINGS; // like the real API: a read after the save returns the saved value
    const calls = stubApi(meWith(["users.manage"]), {
      "GET /admin/security": () => json(200, current),
      "PUT /admin/security": (c) => { current = { ...current, ...(c.body as object) }; return json(200, { ok: true }); },
    });
    renderAt("/security");
    const save = await screen.findByRole("button", { name: "Save" });
    expect(save).toBeDisabled(); // nothing changed yet
    fireEvent.click(screen.getByRole("checkbox", { name: /Require two-factor/ }));
    expect(save).not.toBeDisabled();
    fireEvent.click(save);
    await screen.findByText(/Saved\./);
    expect(calls.find((c) => c.method === "PUT")!.body).toEqual({ mfa_required: true });
    expect(screen.getByLabelText(/Sign out after inactivity/)).toHaveValue(15);
  });
});

describe("Roles", () => {
  const ROLES_DATA = {
    roles: [
      { id: "r-admin", name: "Organization admin", system: true, perms: ["users.manage", "roles.manage"] },
      { id: "r-analyst", name: "Compliance analyst", system: true, perms: ["cases.view", "legacy.perm"] },
    ],
    warnings: ["Organization admin can both manage users and decide cases."],
  };

  it("shows the locked Tenant admin role as read-only to another admin", async () => {
    stubApi(meWith(["roles.manage"]), {
      "GET /admin/roles": () => json(200, { roles: [
        { id: "r-ta", name: "Tenant admin", system: true, locked: true, perms: ["users.manage", "roles.manage"] },
        { id: "r-analyst", name: "Compliance analyst", system: true, perms: ["cases.view"] }], warnings: [] }),
    });
    renderAt("/roles");
    const locked = await screen.findByRole("form", { name: "Role Tenant admin" });
    expect(within(locked).getByText(/locked/)).toBeInTheDocument();
    expect(within(locked).queryByRole("button", { name: "Save role" })).not.toBeInTheDocument();
    expect(within(locked).getByRole("checkbox", { name: /Invite and manage users/ })).toBeDisabled();
    expect(within(screen.getByRole("form", { name: "Role Compliance analyst" })).getByRole("button", { name: "Save role" })).toBeInTheDocument();
  });

  it("hides 'Reveal email' from a user admin who lacks users.pii.reveal", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.endsWith("/auth/refresh")) return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (url.endsWith("/me")) return json(200, { ...meWith(["users.manage"]), permissions: ["users.manage"] });
      if (url.endsWith("/admin/users")) return json(200, USERS);
      if (url.endsWith("/admin/roles")) return json(403, { detail: "no" });
      return json(404, {});
    }));
    renderAt("/users");
    expect(await screen.findByText("Ravi K.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reveal email" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Suspend" })).toBeInTheDocument();   // the other row actions are unaffected
  });

  it("edits another role, keeps unknown permissions, and refuses to edit your own", async () => {
    const calls = stubApi(meWith(["roles.manage"]), {
      "GET /admin/roles": () => json(200, ROLES_DATA),
      "PUT /admin/roles/r-analyst": () => json(200, { ok: true }),
    });
    renderAt("/roles");
    expect(await screen.findByRole("note")).toHaveTextContent("can both manage users and decide cases");

    const own = screen.getByRole("form", { name: "Role Organization admin" });
    expect(within(own).getByText(/your own role/)).toBeInTheDocument();
    expect(within(own).queryByRole("button", { name: "Save role" })).not.toBeInTheDocument();
    expect(within(own).getByRole("checkbox", { name: /Invite and manage users/ })).toBeDisabled();

    const form = screen.getByRole("form", { name: "Role Compliance analyst" });
    expect(within(form).getByRole("checkbox", { name: "legacy.perm" })).toBeChecked(); // no label known: still shown
    const save = within(form).getByRole("button", { name: "Save role" });
    expect(save).toBeDisabled();
    fireEvent.click(within(form).getByRole("checkbox", { name: /Trace wallets/ }));
    fireEvent.click(within(form).getByRole("checkbox", { name: /View alerts, cases and transfers/ })); // untick
    fireEvent.click(save);
    await screen.findByText(/Saved\. People with this role/);
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.body).toEqual({ name: "Compliance analyst", perms: ["legacy.perm", "wallet.trace"] });
  });

  it("creates a custom role and shows the API's refusal", async () => {
    const calls = stubApi(meWith(["roles.manage"]), {
      "GET /admin/roles": () => json(200, { roles: [], warnings: [] }),
      "POST /admin/roles": () => json(409, { detail: "A role with this name already exists" }),
    });
    renderAt("/roles");
    const form = await screen.findByRole("form", { name: "Create a role" });
    expect(within(form).getByRole("button", { name: "Create role" })).toBeDisabled();
    fireEvent.change(within(form).getByLabelText("Role name"), { target: { value: "Fraud reviewer" } });
    fireEvent.click(within(form).getByRole("checkbox", { name: /View alerts, cases and transfers/ }));
    fireEvent.click(within(form).getByRole("button", { name: "Create role" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("A role with this name already exists");
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ name: "Fraud reviewer", perms: ["cases.view"] });
  });
});

describe("Features", () => {
  const FEATURES = [
    { feature: "screening", in_plan: true, enabled: true },
    { feature: "trace", in_plan: true, enabled: false },
    { feature: "export", in_plan: false, enabled: false },
  ];

  it("toggles a feature, locks ones outside the plan, and refreshes the menu from /me", async () => {
    let features = ["screening"];
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const path = new URL(url).pathname;
      const method = init?.method ?? "GET";
      if (path === "/auth/refresh") return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (path === "/me") return json(200, { ...meWith(["features.manage", "wallet.trace"], features) });
      calls.push(`${method} ${path} ${init?.body ?? ""}`);
      if (method === "PUT") { features = ["screening", "trace"]; return json(200, { ok: true }); }
      return json(200, FEATURES.map((f) => (f.feature === "trace" && features.includes("trace") ? { ...f, enabled: true } : f)));
    }));
    renderAt("/features");
    const trace = await screen.findByRole("checkbox", { name: /Wallet trace/ });
    expect(screen.getByRole("checkbox", { name: /Case export/ })).toBeDisabled();
    expect(screen.getByText(/not in your plan/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Wallet trace" })).not.toBeInTheDocument();
    fireEvent.click(trace);
    expect(await screen.findByRole("link", { name: "Wallet trace" })).toBeInTheDocument(); // /me re-read
    expect(calls).toContain('PUT /admin/features {"feature":"trace","enabled":true}');
  });

  it("shows why a toggle was refused", async () => {
    stubApi(meWith(["features.manage"]), {
      "GET /admin/features": () => json(200, FEATURES),
      "PUT /admin/features": () => json(403, { detail: "This feature isn't in your plan" }),
    });
    renderAt("/features");
    fireEvent.click(await screen.findByRole("checkbox", { name: /Wallet trace/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("This feature isn't in your plan");
  });
});

describe("Users: sensitive actions", () => {
  it("reveals an email only with a reason, shows it once, and clears it on Done", async () => {
    const calls = stubApi(meWith(["users.manage", "roles.manage"]), {
      "POST /admin/users/u2/reveal-email": () => json(200, { email: "ravi.k@northwindremit.ca" }),
    });
    renderAt("/users");
    const row = (await screen.findByText("Ravi K.", { selector: "td" })).closest("tr")!;
    expect(within(screen.getByText("Asha Admin", { selector: "td" }).closest("tr")!).queryByRole("button", { name: "Reveal email" })).toBeNull();
    fireEvent.click(within(row).getByRole("button", { name: "Reveal email" }));
    const form = screen.getByRole("form", { name: "Reveal email" });
    expect(within(form).getByRole("button", { name: "Reveal" })).toBeDisabled(); // no reason yet
    fireEvent.change(within(form).getByLabelText(/Reason/), { target: { value: "Customer asked us to confirm the address" } });
    fireEvent.click(within(form).getByRole("button", { name: "Reveal" }));
    expect(await screen.findByTestId("revealed-email")).toHaveTextContent("ravi.k@northwindremit.ca");
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ reason: "Customer asked us to confirm the address" });
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() => expect(document.body.textContent).not.toContain("ravi.k@"));
  });

  it("resets two-factor with a reason, only for people who have it, and shows the API's refusal", async () => {
    const calls = stubApi(meWith(["users.manage", "roles.manage"]), {
      "GET /admin/users": () => json(200, [
        { id: "me", name: "Asha Admin", email: "a•••@x.ca", role: "Organization admin", status: "active", mfa: true, last_login: null },
        { id: "u2", name: "Ravi K.", email: "r•••@x.ca", role: "Compliance analyst", status: "active", mfa: true, last_login: null },
        { id: "u3", name: "Nia P.", email: "n•••@x.ca", role: "Compliance analyst", status: "active", mfa: false, last_login: null },
      ]),
      "POST /admin/users/u2/reset-mfa": () => json(409, { detail: "This person signs in with company SSO. Their company manages two-factor" }),
    });
    renderAt("/users");
    const nia = (await screen.findByText("Nia P.", { selector: "td" })).closest("tr")!;
    expect(within(nia).queryByRole("button", { name: "Reset two-factor" })).toBeNull(); // two-factor already off
    const ravi = screen.getByText("Ravi K.", { selector: "td" }).closest("tr")!;
    fireEvent.click(within(ravi).getByRole("button", { name: "Reset two-factor" }));
    const form = screen.getByRole("form", { name: "Reset two-factor" });
    fireEvent.change(within(form).getByLabelText(/Reason/), { target: { value: "Lost phone, identity verified" } });
    fireEvent.click(within(form).getByRole("button", { name: "Reset two-factor" }));
    expect(await within(form).findByRole("alert")).toHaveTextContent("company SSO");
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ reason: "Lost phone, identity verified" });
  });
});

describe("Security settings: other fields", () => {
  const SETTINGS = {
    mfa_required: false, sso_enabled: false, idle_timeout_min: 15, min_password_len: 14, ip_allowlist: ["10.0.0.0/8"], retention_years: 7, dormant_days: 90, access_review_days: 90, export_limit_per_hour: 20, anomaly_searches_per_hour: 100, anomaly_exports_per_hour: 10, alert_new_country: true,
    encryption: { algorithm: "AES-256-GCM", current_key: "v1", key_manager: "local (dev only)" },
  };

  it("sends only the fields that changed, with the allowlist as a list", async () => {
    const calls = stubApi(meWith(["users.manage"]), {
      "GET /admin/security": () => json(200, SETTINGS),
      "PUT /admin/security": () => json(200, { ok: true }),
    });
    renderAt("/security");
    const save = await screen.findByRole("button", { name: "Save" });
    expect(screen.getByLabelText("Allowed networks")).toHaveValue("10.0.0.0/8");
    fireEvent.change(screen.getByLabelText(/Minimum password length/), { target: { value: "16" } });
    fireEvent.change(screen.getByLabelText("Allowed networks"), { target: { value: "10.0.0.0/8\n203.0.113.0/24, 198.51.100.7/32" } });
    fireEvent.click(save);
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    expect(calls.find((c) => c.method === "PUT")!.body).toEqual({
      min_password_len: 16, ip_allowlist: ["10.0.0.0/8", "203.0.113.0/24", "198.51.100.7/32"],
    });
  });

  it("clears the allowlist with an empty list and shows the lock-out refusal", async () => {
    const calls = stubApi(meWith(["users.manage"]), {
      "GET /admin/security": () => json(200, SETTINGS),
      "PUT /admin/security": () => json(409, { detail: "This allowlist would lock you out. Include your current network" }),
    });
    renderAt("/security");
    fireEvent.change(await screen.findByLabelText("Allowed networks"), { target: { value: "192.0.2.0/24" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("lock you out");
    fireEvent.change(screen.getByLabelText("Allowed networks"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PUT")).toHaveLength(2));
    expect(calls.filter((c) => c.method === "PUT")[1].body).toEqual({ ip_allowlist: [] });
  });
});

describe("Company sign-in (SSO)", () => {
  it("saves the domain, shows the DNS record once, and verifies it", async () => {
    let dnsReady = false;
    const calls = stubApi(meWith(["users.manage"]), {
      "PUT /admin/sso": () => json(200, { txt_record: { name: "_sentrail.northwindremit.ca", value: "sentrail-verify=abc123" }, next: "x" }),
      "POST /admin/sso/verify": () => dnsReady
        ? json(200, { verified: "northwindremit.ca" })
        : json(409, { detail: "The TXT record wasn't found yet. DNS changes can take up to an hour" }),
    });
    renderAt("/sso");
    fireEvent.change(await screen.findByLabelText("Email domain"), { target: { value: " NorthwindRemit.ca " } });
    fireEvent.change(screen.getByLabelText(/Identity provider name/), { target: { value: "northwind-entra" } });
    fireEvent.click(screen.getByRole("button", { name: "Save and get DNS record" }));
    expect(await screen.findByTestId("txt-name")).toHaveTextContent("_sentrail.northwindremit.ca");
    expect(screen.getByTestId("txt-value")).toHaveTextContent("sentrail-verify=abc123");
    // lowercased and trimmed; "enforced" is never switched on because the API doesn't enforce it yet
    expect(calls.find((c) => c.method === "PUT")!.body).toEqual({ domain: "northwindremit.ca", idp_alias: "northwind-entra", enforced: false });

    fireEvent.click(screen.getByRole("button", { name: "Check DNS record" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("TXT record wasn't found yet");
    dnsReady = true;
    fireEvent.click(screen.getByRole("button", { name: "Check DNS record" }));
    expect(await screen.findByText(/Verified: northwindremit\.ca/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Check DNS record" })).not.toBeInTheDocument();
  });

  it("shows the API's refusal when the domain is taken", async () => {
    stubApi(meWith(["users.manage"]), { "PUT /admin/sso": () => json(422, { detail: "That domain isn't valid" }) });
    renderAt("/sso");
    fireEvent.change(await screen.findByLabelText("Email domain"), { target: { value: "example.com" } });
    fireEvent.change(screen.getByLabelText(/Identity provider name/), { target: { value: "idp-one" } });
    fireEvent.click(screen.getByRole("button", { name: "Save and get DNS record" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("That domain isn't valid");
    expect(screen.queryByTestId("txt-name")).not.toBeInTheDocument();
  });

  it("explains a badly typed domain without calling the API", async () => {
    const calls = stubApi(meWith(["users.manage"]));
    renderAt("/sso");
    fireEvent.change(await screen.findByLabelText("Email domain"), { target: { value: "me@example.com" } });
    fireEvent.change(screen.getByLabelText(/Identity provider name/), { target: { value: "idp-one" } });
    fireEvent.click(screen.getByRole("button", { name: "Save and get DNS record" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Enter just the domain");
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
  });
});
