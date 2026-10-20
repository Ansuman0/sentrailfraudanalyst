/** Every Sentrail API call the app makes, in one place. Components use these through React Query hooks. */
import { request } from "./http";
import type {
  AdminUser, Alert, AlertStatus, ApiKey, AuditEvent, Band, CaseDetail, Investigation, LoginResponse, Me, Organization, Policy,
  Plan, PlatformSecurity, RoleSummary, SearchResult, SecuritySettings, Session, TokenResponse, TraceResult,
} from "../types/api";

// ---- sign-in ----
export const auth = {
  login: (email: string, password: string) =>
    request<LoginResponse>("/auth/login", {
      method: "POST", body: { email, password }, withCookies: true, retryOn401: false,
    }),
  mfa: (mfa_token: string, code: { code?: string; recovery_code?: string }) =>
    request<TokenResponse>("/auth/mfa", {
      method: "POST", body: { mfa_token, ...code }, withCookies: true, retryOn401: false,
    }),
  discover: (email: string) =>
    request<{ method: "sso" | "keycloak"; next: string }>("/auth/discover", {
      method: "POST", body: { email }, retryOn401: false,
    }),
  logout: () => request<{ signed_out: boolean }>("/auth/logout", { method: "POST", withCookies: true, retryOn401: false }),
};

// ---- invitation enrollment (the token is the credential; no session yet). Two-factor comes after sign-in. ----
export const invitations = {
  accept: (token: string, full_name: string, password: string) =>
    request<{ activated: boolean; next: string }>("/invitations/accept", {
      method: "POST", body: { token, full_name, password }, retryOn401: false,
    }),
};

// ---- me ----
export const me = {
  get: () => request<Me>("/me"),
  sessions: () => request<Session[]>("/me/sessions"),
  endSession: (id: string) => request<{ ok: boolean }>(`/me/sessions/${encodeURIComponent(id)}`, { method: "DELETE" }),
  endOthers: () => request<{ ended: number }>("/me/sessions/end-others", { method: "POST" }),
  /** Start two-factor setup: a new authenticator secret (replaces any unconfirmed one). */
  mfaSetup: () => request<{ otpauth_uri: string; secret: string }>("/me/mfa/setup", { method: "POST" }),
  /** Confirm with a code: two-factor on, other sessions ended, a new two-factor session for this device. */
  mfaConfirm: (code: string) =>
    request<TokenResponse & { recovery_codes: string[] }>("/me/mfa/confirm", { method: "POST", body: { code }, withCookies: true }),
};

// ---- cases ----
export const cases = {
  alerts: (status: AlertStatus, band?: Band) => request<Alert[]>("/alerts", { query: { status, band } }),
  get: (id: string) => request<CaseDetail>(`/cases/${encodeURIComponent(id)}`),
  decide: (id: string, decision: "false_positive" | "request_info" | "escalate", reason: string) =>
    request<{ status: AlertStatus }>(`/cases/${encodeURIComponent(id)}/decision`, { method: "POST", body: { decision, reason } }),
  investigate: (id: string) => request<Investigation>(`/cases/${encodeURIComponent(id)}/investigate`, { method: "POST" }),
  submitStr: (id: string, final_text: string) =>
    request<{ status: AlertStatus }>(`/cases/${encodeURIComponent(id)}/str/submit`, { method: "POST", body: { final_text } }),
  approveStr: (id: string) => request<{ status: AlertStatus }>(`/cases/${encodeURIComponent(id)}/str/approve`, { method: "POST" }),
};

// ---- investigate ----
export const investigate = {
  search: (q: string, reason: string) => request<SearchResult>("/search", { query: { q, reason } }),
  trace: (address: string, hops: number) =>
    request<TraceResult>(`/wallets/${encodeURIComponent(address)}/trace`, { query: { hops } }),
};

// ---- govern ----
export const govern = {
  policy: () => request<Policy>("/policy"),
  setPolicy: (p: Policy) => request<Policy>("/policy", { method: "PUT", body: p }),
  audit: (limit = 200) => request<AuditEvent[]>("/admin/audit", { query: { limit } }),
  verifyAudit: () => request<{ ok: boolean; events?: number; broken_at?: number; reason?: string }>("/admin/audit/verify"),
};

// ---- platform ----
export const platform = {
  orgs: () => request<Organization[]>("/platform/orgs"),
  plans: () => request<Plan[]>("/platform/plans"),
  security: () => request<PlatformSecurity>("/platform/security"),
  /** Must carry every field: the API resets any it doesn't receive. */
  setSecurity: (s: Omit<PlatformSecurity, "mfa">) =>
    request<{ ok: boolean; tenants_checked: number }>("/platform/security", { method: "PUT", body: s }),
  /** Replaces the plan's feature list for every organization on it; features removed switch off for them. */
  setPlanFeatures: (key: string, features: string[]) =>
    request<{ ok: boolean }>(`/platform/plans/${encodeURIComponent(key)}`, { method: "PUT", body: { features } }),
  setOrgPlan: (orgId: string, plan: string) =>
    request<{ ok: boolean }>(`/platform/orgs/${encodeURIComponent(orgId)}/plan`, { method: "PUT", body: { plan } }),
};

/** Only the fields being changed; the API keeps the rest. */
export interface SecurityPatch {
  mfa_required?: boolean;
  idle_timeout_min?: number;
  min_password_len?: number;
  retention_years?: number;
  ip_allowlist?: string[];
}

// ---- organization administration ----
export const admin = {
  users: () => request<AdminUser[]>("/admin/users"),
  /** Needs roles.manage: a user admin without it can't pick roles. */
  roles: () => request<{ roles: RoleSummary[]; warnings: string[] }>("/admin/roles"),
  features: () => request<{ feature: string; in_plan: boolean; enabled: boolean }[]>("/admin/features"),
  setFeature: (feature: string, enabled: boolean) =>
    request<{ ok: boolean }>("/admin/features", { method: "PUT", body: { feature, enabled } }),
  revealEmail: (id: string, reason: string) =>
    request<{ email: string }>(`/admin/users/${encodeURIComponent(id)}/reveal-email`, { method: "POST", body: { reason } }),
  resetMfa: (id: string, reason: string) =>
    request<{ ok: boolean }>(`/admin/users/${encodeURIComponent(id)}/reset-mfa`, { method: "POST", body: { reason } }),
  setSso: (domain: string, idp_alias: string) =>
    request<{ txt_record: { name: string; value: string }; next: string }>("/admin/sso", {
      method: "PUT", body: { domain, idp_alias, enforced: false },
    }),
  verifySso: () => request<{ verified: string }>("/admin/sso/verify", { method: "POST" }),
  createRole: (name: string, perms: string[]) =>
    request<{ id: string }>("/admin/roles", { method: "POST", body: { name, perms } }),
  updateRole: (id: string, name: string, perms: string[]) =>
    request<{ ok: boolean }>(`/admin/roles/${encodeURIComponent(id)}`, { method: "PUT", body: { name, perms } }),
  invite: (email: string, role_id: string) =>
    request<{ invited: string; dev_link?: string }>("/admin/invitations", { method: "POST", body: { email, role_id } }),
  updateUser: (id: string, patch: { role_id?: string; status?: "active" | "suspended" }) =>
    request<{ ok: boolean }>(`/admin/users/${encodeURIComponent(id)}`, { method: "PATCH", body: patch }),
  apiKeys: () => request<ApiKey[]>("/admin/api-keys"),
  createApiKey: (label: string) =>
    request<{ api_key: string; prefix: string; message: string }>("/admin/api-keys", { method: "POST", body: label ? { label } : {} }),
  revokeApiKey: (prefix: string) => request<{ revoked: string }>(`/admin/api-keys/${encodeURIComponent(prefix)}`, { method: "DELETE" }),
  security: () => request<SecuritySettings>("/admin/security"),
  setSecurity: (patch: SecurityPatch) => request<{ ok: boolean }>("/admin/security", { method: "PUT", body: patch }),
};
