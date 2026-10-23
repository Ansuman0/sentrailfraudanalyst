import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { AuthProvider } from "../hooks/useAuth";
import { setAccessToken } from "../services/http";
import { getPasskey } from "../services/webauthn";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const bytes = (...n: number[]) => new Uint8Array(n).buffer;
const OPTIONS = { challenge: "AQID", rpId: "localhost", userVerification: "required", allowCredentials: [{ id: "BAUG", type: "public-key" }] };
const credentials = { get: vi.fn(), create: vi.fn() };

beforeEach(() => {
  vi.stubGlobal("PublicKeyCredential", class {});
  Object.defineProperty(navigator, "credentials", { value: credentials, configurable: true });
  credentials.get.mockReset();
  credentials.get.mockResolvedValue({
    id: "BAUG", rawId: bytes(4, 5, 6), type: "public-key", getClientExtensionResults: () => ({}),
    response: { clientDataJSON: bytes(1, 2), authenticatorData: bytes(3, 4), signature: bytes(5, 6), userHandle: null },
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  setAccessToken(null);
});

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

const ME = {
  user_id: "u1", name: "Owner", email: "o•••@x.example", role: "Platform owner", tenant: { name: "Platform console", slug: "platform", environment: "platform", brand_color: "#534AB7" },
  permissions: [], features: [], mfa_enabled: true, mfa_setup: null, session_mfa: true, passkeys: 0, must_enroll_passkey: false,
};

describe("webauthn helper", () => {
  it("hands the browser binary challenge and credential ids, and returns base64url JSON", async () => {
    const out = (await getPasskey(OPTIONS)) as { id: string; rawId: string; response: Record<string, string> };
    const call = credentials.get.mock.calls[0][0].publicKey;
    expect(call.challenge).toBeInstanceOf(ArrayBuffer);
    expect(Array.from(new Uint8Array(call.challenge))).toEqual([1, 2, 3]);
    expect(Array.from(new Uint8Array(call.allowCredentials[0].id))).toEqual([4, 5, 6]);
    expect(out.rawId).toBe("BAUG");
    expect(out.response.signature).toBe("BQY");
    expect(out.response.clientDataJSON).toBe("AQI");
  });
});

describe("sign-in with a passkey", () => {
  const stub = (loginBody: unknown, extra: Record<string, () => Response> = {}) => {
    const calls: { url: string; body: any }[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const path = new URL(url).pathname;
      if (path === "/auth/refresh") return json(401, {});
      calls.push({ url: path, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      if (path === "/auth/login") return json(200, loginBody);
      if (extra[path]) return extra[path]();
      return json(404, {});
    }));
    return calls;
  };
  const signIn = async () => {
    renderAt("/signin");
    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "owner@x.example" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "a long enough password" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
  };

  it("offers only the passkey to someone whose only second factor is a passkey, and signs in with it", async () => {
    let signedIn = false;
    const calls = stub({ mfa_token: "m1", methods: ["passkey"], passkey_options: OPTIONS, next: "Use your passkey" }, {
      "/auth/passkey": () => { signedIn = true; return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600, route: "console" }); },
      "/me": () => json(200, ME),
    });
    await signIn();
    const button = await screen.findByRole("button", { name: "Use your passkey" });
    expect(screen.queryByLabelText("Code")).not.toBeInTheDocument();
    fireEvent.click(button);
    await waitFor(() => expect(signedIn).toBe(true));
    const sent = calls.find((c) => c.url === "/auth/passkey")!.body;
    expect(sent.mfa_token).toBe("m1");
    expect(sent.credential.response.signature).toBe("BQY");
  });

  it("offers a code as well when an authenticator app is set up", async () => {
    stub({ mfa_token: "m1", methods: ["totp", "passkey"], passkey_options: OPTIONS, next: "x" });
    await signIn();
    expect(await screen.findByRole("button", { name: "Use your passkey" })).toBeInTheDocument();
    expect(screen.getByLabelText("Code")).toBeInTheDocument();
  });

  it("explains a cancelled prompt in plain words", async () => {
    credentials.get.mockRejectedValue(Object.assign(new Error("x"), { name: "NotAllowedError" }));
    stub({ mfa_token: "m1", methods: ["passkey"], passkey_options: OPTIONS, next: "x" });
    await signIn();
    fireEvent.click(await screen.findByRole("button", { name: "Use your passkey" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("cancelled or timed out");
  });
});

describe("owners without a passkey", () => {
  it("are taken to the screen that registers one, and nothing else", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      const path = new URL(url).pathname;
      if (path === "/auth/refresh") return json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 });
      if (path === "/me") return json(200, { ...ME, must_enroll_passkey: true });
      return json(404, {});
    }));
    renderAt("/organizations");
    expect(await screen.findByRole("heading", { name: "Register a passkey" })).toBeInTheDocument();
    expect(screen.getByRole("form", { name: "Add a passkey" })).toBeInTheDocument();
  });
});
