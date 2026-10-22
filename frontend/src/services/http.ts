/**
 * The one place the app talks HTTP to the Sentrail API.
 *
 * - The access token lives in memory only (never localStorage/sessionStorage), so a script injected
 *   into the page can't read a long-lived credential from storage.
 * - The refresh token is an HttpOnly, SameSite=Strict cookie scoped to the API's /auth path. It is
 *   rotated on every use and the API treats a reused token as theft (it ends the whole session),
 *   so refreshes are single-flight: concurrent callers share one in-flight request.
 * - A 401 on a normal call triggers one refresh and one retry.
 */
import type { TokenResponse } from "../types/api";

/**
 * Picks the API base for the page that is open. The configured URL (VITE_API_BASE_URL, e.g. https://api.sentrail.qatech.world)
 * is used on the app's own domain and in local development. If the page is opened from some other host (the AWS public
 * hostname while the domain's DNS is still propagating), the API is reached on that same origin under /api, where the
 * reverse proxy forwards it (infra/caddy/Caddyfile), so the app works without the domain.
 */
export function resolveApiBase(configured: string, pageHost: string, pageOrigin: string): string {
  const base = configured.replace(/\/+$/, "");
  let apiHost: string;
  try {
    apiHost = new URL(base).hostname;
  } catch {
    return base;
  }
  const isLocal = (h: string) => h === "localhost" || h === "127.0.0.1" || h === "[::1]" || h === "::1";
  if (isLocal(apiHost) || isLocal(pageHost)) return base;
  // The app host is the API host without its first label (api.sentrail.qatech.world -> sentrail.qatech.world).
  const appHost = apiHost.split(".").slice(1).join(".");
  if (!appHost || pageHost === apiHost || pageHost === appHost || pageHost.endsWith("." + appHost)) return base;
  return `${pageOrigin}/api`;
}

export const API_BASE_URL = resolveApiBase(
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000",
  typeof window === "undefined" ? "localhost" : window.location.hostname,
  typeof window === "undefined" ? "http://localhost" : window.location.origin,
);

export class ApiError extends Error {
  constructor(public status: number, message: string, public detail?: unknown) {
    super(message);
    this.name = "ApiError";
  }
}

let accessToken: string | null = null;
let refreshing: Promise<boolean> | null = null;
const signedOutListeners = new Set<() => void>();

export function setAccessToken(token: string | null) {
  accessToken = token;
}

export function hasAccessToken() {
  return accessToken !== null;
}

/** Called when the session can't be renewed (expired, revoked, signed out elsewhere). */
export function onSignedOut(listener: () => void) {
  signedOutListeners.add(listener);
  return () => signedOutListeners.delete(listener);
}

/** FastAPI errors are {"detail": string} or {"detail": [{msg, loc}]} (validation) or {"detail": [strings]}. */
export function errorMessage(detail: unknown, fallback: string): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const parts = detail.map((d) => (typeof d === "string" ? d : (d as { msg?: string })?.msg)).filter(Boolean);
    if (parts.length) return parts.join(". ");
  }
  return fallback;
}

/**
 * Swap the refresh cookie for a new access token. Single-flight within this tab (shared promise) and
 * across tabs (Web Locks): a second tab waits, then sends the cookie the first one already rotated.
 */
export function refreshSession(): Promise<boolean> {
  if (!refreshing) {
    const send = () => fetch(`${API_BASE_URL}/auth/refresh`, { method: "POST", credentials: "include" });
    const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
    refreshing = (locks ? locks.request("sentrail-refresh", send) : send())
      .then(async (r) => {
        if (!r.ok) {
          accessToken = null;
          return false;
        }
        accessToken = ((await r.json()) as TokenResponse).access_token;
        return true;
      })
      .catch(() => false)
      .finally(() => {
        refreshing = null;
      });
  }
  return refreshing;
}

type Query = Record<string, string | number | boolean | null | undefined>;

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  query?: Query;
  /** Send cookies (only the /auth endpoints use them). */
  withCookies?: boolean;
  /** Retry once after refreshing on 401 (off for the sign-in calls themselves). */
  retryOn401?: boolean;
}

function buildUrl(path: string, query?: Query) {
  const url = new URL(API_BASE_URL + path);
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
  }
  return url.toString();
}

function hex(bytes: number) {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Correlation ids for one call: the API logs them, so a user's failed request can be found by id. */
function correlationHeaders(): Record<string, string> {
  const trace = hex(16);
  return { "X-Request-ID": hex(16), traceparent: `00-${trace}-${hex(8)}-01` };
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, query, withCookies = false, retryOn401 = true } = opts;
  const ids = correlationHeaders();            // same ids on the 401 retry: it is the same user action
  const send = () => {
    const headers: Record<string, string> = { ...ids };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (accessToken) headers["Authorization"] = `Bearer ${accessToken}`;
    return fetch(buildUrl(path, query), {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: withCookies ? "include" : "omit",
    });
  };

  let r: Response;
  try {
    r = await send();
  } catch {
    throw new ApiError(0, "The Sentrail API can't be reached. Check that it is running and try again");
  }
  if (r.status === 401 && retryOn401 && accessToken !== null) {
    if (await refreshSession()) {
      r = await send();
    } else {
      signedOutListeners.forEach((l) => l());
    }
  }
  if (!r.ok) {
    let detail: unknown;
    try {
      detail = ((await r.json()) as { detail?: unknown }).detail;
    } catch {
      /* not JSON */
    }
    throw new ApiError(r.status, errorMessage(detail, `Request failed (${r.status})`), detail);
  }
  if (r.status === 204) return undefined as T;
  return (await r.json()) as T;
}

/** Full URL for a browser navigation to the API (OIDC sign-in and sign-out are redirects, not fetches). */
export function apiUrl(path: string) {
  return API_BASE_URL + path;
}
