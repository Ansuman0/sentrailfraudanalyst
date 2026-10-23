import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, errorMessage, hasAccessToken, onSignedOut, refreshSession, request, resolveApiBase, setAccessToken, setStepUpHandler } from "./http";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

afterEach(() => {
  vi.unstubAllGlobals();
  setAccessToken(null);
  setStepUpHandler(null);
});

describe("refreshSession", () => {
  it("is single-flight: concurrent callers share one request (a second use of the cookie would end the session)", async () => {
    let resolve!: (r: Response) => void;
    const fetchMock = vi.fn(() => new Promise<Response>((r) => (resolve = r)));
    vi.stubGlobal("fetch", fetchMock);
    const a = refreshSession();
    const b = refreshSession();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    resolve(json(200, { access_token: "new", token_type: "Bearer", expires_in: 600 }));
    expect(await a).toBe(true);
    expect(await b).toBe(true);
    expect(hasAccessToken()).toBe(true);
  });

  it("sends cookies to /auth/refresh only", async () => {
    const fetchMock = vi.fn(async () => json(401, { detail: "Sign in again" }));
    vi.stubGlobal("fetch", fetchMock);
    expect(await refreshSession()).toBe(false);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toMatch(/\/auth\/refresh$/);
    expect(init.credentials).toBe("include");
    expect(hasAccessToken()).toBe(false);
  });
});

describe("request", () => {
  it("sends the in-memory bearer token and no cookies", async () => {
    setAccessToken("tok");
    const fetchMock = vi.fn(async () => json(200, { ok: true }));
    vi.stubGlobal("fetch", fetchMock);
    await request("/me");
    const init = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok");
    expect(init.credentials).toBe("omit");
  });

  it("refreshes once on 401 and retries with the new token", async () => {
    setAccessToken("old");
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json(401, { detail: "Session expired" }))
      .mockResolvedValueOnce(json(200, { access_token: "new", token_type: "Bearer", expires_in: 600 }))
      .mockResolvedValueOnce(json(200, { id: 1 }));
    vi.stubGlobal("fetch", fetchMock);
    expect(await request("/alerts")).toEqual({ id: 1 });
    const retry = fetchMock.mock.calls[2][1] as RequestInit;
    expect((retry.headers as Record<string, string>).Authorization).toBe("Bearer new");
  });

  it("signals sign-out when the session can't be renewed", async () => {
    setAccessToken("old");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(json(401, {})).mockResolvedValueOnce(json(401, {})).mockResolvedValue(json(401, {})));
    const listener = vi.fn();
    const off = onSignedOut(listener);
    await expect(request("/alerts")).rejects.toBeInstanceOf(ApiError);
    expect(listener).toHaveBeenCalledOnce();
    off();
  });

  it("turns FastAPI errors into readable messages and keeps the status", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(409, { detail: "This alert is closed" })));
    await expect(request("/cases/A-1/decision", { method: "POST", body: {} })).rejects.toMatchObject({
      status: 409, message: "This alert is closed",
    });
  });

  it("reports an unreachable API clearly", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("Failed to fetch"); }));
    await expect(request("/me")).rejects.toMatchObject({ status: 0 });
  });
});

describe("correlation ids", () => {
  it("sends a request id and W3C traceparent, and reuses them on the retry after a 401", async () => {
    setAccessToken("old");
    const seen: Record<string, string>[] = [];
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).endsWith("/auth/refresh")) return json(200, { access_token: "new", token_type: "Bearer", expires_in: 600 });
      seen.push(init?.headers as Record<string, string>);
      return seen.length === 1 ? json(401, { detail: "expired" }) : json(200, { ok: true });
    });
    vi.stubGlobal("fetch", fetchMock);
    await request("/alerts");
    expect(seen).toHaveLength(2);
    expect(seen[0]["X-Request-ID"]).toMatch(/^[0-9a-f]{32}$/);
    expect(seen[0].traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
    expect(seen[1]["X-Request-ID"]).toBe(seen[0]["X-Request-ID"]);
    expect(seen[1].Authorization).toBe("Bearer new");
  });
});

describe("errorMessage", () => {
  it("reads string, validation-list and string-list details", () => {
    expect(errorMessage("Nope", "x")).toBe("Nope");
    expect(errorMessage([{ msg: "field required" }], "x")).toBe("field required");
    expect(errorMessage(["Use at least 14 characters", "Don't include your name"], "x"))
      .toBe("Use at least 14 characters. Don't include your name");
    expect(errorMessage(undefined, "fallback")).toBe("fallback");
  });
});

describe("resolveApiBase", () => {
  const api = "https://api.sentrail.qatech.world";
  it("keeps the configured API on the app's own domain", () => {
    expect(resolveApiBase(api, "sentrail.qatech.world", "https://sentrail.qatech.world")).toBe(api);
  });
  it("uses same-origin /api on the AWS public hostname (domain not resolving yet)", () => {
    const host = "ec2-44-196-164-178.compute-1.amazonaws.com";
    expect(resolveApiBase(api + "/", host, `https://${host}`)).toBe(`https://${host}/api`);
  });
  it("leaves local development alone", () => {
    expect(resolveApiBase("http://localhost:8000", "localhost", "http://localhost:5173")).toBe("http://localhost:8000");
    expect(resolveApiBase(api, "localhost", "http://localhost:5173")).toBe(api);
  });
});

describe("CSRF header", () => {
  it("is sent on the refresh call and on every call that uses cookies, and on nothing else", async () => {
    const fetchMock = vi.fn(async () => json(200, { access_token: "t", token_type: "Bearer", expires_in: 600 }));
    vi.stubGlobal("fetch", fetchMock);
    await refreshSession();
    const refreshInit = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect((refreshInit.headers as Record<string, string>)["X-Sentrail-CSRF"]).toBe("1");
    await request("/auth/logout", { method: "POST", withCookies: true, retryOn401: false });
    await request("/me");
    const headersOf = (i: number) => ((fetchMock.mock.calls[i] as unknown as [string, RequestInit])[1].headers as Record<string, string>);
    expect(headersOf(1)["X-Sentrail-CSRF"]).toBe("1");
    expect(headersOf(2)["X-Sentrail-CSRF"]).toBeUndefined();
  });
});

describe("step-up", () => {
  const stepUp401 = () => json(401, { error: "step_up_required" });

  it("asks once for a second factor, then repeats the call with the new token", async () => {
    setAccessToken("old");
    let calls = 0;
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      calls += 1;
      const auth = (init?.headers as Record<string, string>)["Authorization"];
      return auth === "Bearer fresh" ? json(200, { ok: true }) : stepUp401();
    });
    vi.stubGlobal("fetch", fetchMock);
    const handler = vi.fn(async () => {
      setAccessToken("fresh");
      return true;
    });
    setStepUpHandler(handler);
    expect(await request<{ ok: boolean }>("/policy", { method: "PUT", body: {} })).toEqual({ ok: true });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(calls).toBe(2);
    expect(fetchMock.mock.calls.some(([u]) => String(u).endsWith("/auth/refresh"))).toBe(false); // not mistaken for an expired session
  });

  it("gives up with a clear message when the person cancels", async () => {
    setAccessToken("old");
    vi.stubGlobal("fetch", vi.fn(async () => stepUp401()));
    setStepUpHandler(async () => false);
    await expect(request("/policy", { method: "PUT", body: {} })).rejects.toMatchObject({
      status: 401, message: "Confirm with your authenticator app to do this.",
    });
  });

  it("does nothing special when no dialog is registered", async () => {
    setAccessToken("old");
    vi.stubGlobal("fetch", vi.fn(async () => stepUp401()));
    await expect(request("/policy", { method: "PUT", body: {} })).rejects.toBeInstanceOf(ApiError);
  });
});
