/** Every Sentrail API call the app makes, in one place. Components use these through React Query hooks. */
import { request } from "./http";
import type {
  AccessRequest, AdminUser, Alert, Approval, DownloadLink, Effective, ReviewDetail, ReviewSummary, StaffUser, Team, TeamDetail, AlertStatus, ApiKey, AuditEvent, Band, CaseDetail, Investigation, LoginResponse, Me, Organization, Policy,
  Passkey, Plan, PlatformSecurity, RoleSummary, SearchResult, SecuritySettings, Session, TenantChoice, TokenResponse, TraceResult,
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
    request<{ method: "sso" | "keycloak"; enforced?: boolean; next: string }>("/auth/discover", {
      method: "POST", body: { email }, retryOn401: false,
    }),
  logout: () => request<{ signed_out: boolean }>("/auth/logout", { method: "POST", withCookies: true, retryOn401: false }),
  /** Prove a second factor again for a sensitive action; the answer carries a fresh access token. */
  stepUp: (code: { code?: string; recovery_code?: string; credential?: Record<string, unknown> }) =>
    request<TokenResponse>("/session/step-up", { method: "POST", body: code, retryOn401: false }),
  stepUpOptions: () => request<Record<string, any>>("/session/step-up/options", { method: "POST", retryOn401: false }),
  /** Second step of a sign-in with a passkey. */
  passkey: (mfa_token: string, credential: Record<string, unknown>) =>
    request<TokenResponse>("/auth/passkey", { method: "POST", body: { mfa_token, credential }, withCookies: true, retryOn401: false }),
};

// ---- passkeys ----
export const passkeys = {
  list: () => request<{ passkeys: Passkey[]; allowed: boolean }>("/me/passkeys"),
  options: () => request<Record<string, any>>("/me/passkeys/options", { method: "POST", retryOn401: false }),
  /** The answer carries a new two-factor session when this was the person's first second factor. */
  register: (credential: Record<string, unknown>, name: string) =>
    request<Passkey & { session?: TokenResponse }>("/me/passkeys", { method: "POST", body: { credential, name }, withCookies: true, retryOn401: false }),
  remove: (id: string) => request<{ removed: string }>(`/me/passkeys/${encodeURIComponent(id)}`, { method: "DELETE" }),
};

// ---- an owner's access session inside a tenant ----
export const accessSession = {
  /** End the session I'm working in (self-service). */
  end: () => request<{ ended: string }>("/me/access-session", { method: "DELETE", retryOn401: false }),
};

// ---- tenants: the places this person can work, and moving between them (a new session each time) ----
export const tenants = {
  list: () => request<{ tenants: TenantChoice[] }>("/me/tenants"),
  /** tenantId null = the platform console. */
  switchTo: (tenantId: string | null) =>
    request<TokenResponse>("/session/tenant", { method: "POST", body: { tenant_id: tenantId }, withCookies: true, retryOn401: false }),
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
  alerts: (status: AlertStatus, band?: Band, team?: string) => request<Alert[]>("/alerts", { query: { status, band, team } }),
  setTeam: (id: string, team_id: string | null) =>
    request<{ team_id: string | null }>(`/cases/${encodeURIComponent(id)}/team`, { method: "PUT", body: { team_id } }),
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
  dormant_days?: number;
  access_review_days?: number;
  export_limit_per_hour?: number;
  anomaly_searches_per_hour?: number;
  anomaly_exports_per_hour?: number;
  alert_new_country?: boolean;
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
    request<{ id: string; warnings?: string[] }>("/admin/roles", { method: "POST", body: { name, perms } }),
  updateRole: (id: string, name: string, perms: string[]) =>
    request<{ ok: boolean; warnings?: string[] }>(`/admin/roles/${encodeURIComponent(id)}`, { method: "PUT", body: { name, perms } }),
  invite: (email: string, role_id: string) =>
    request<{ invited: string; dev_link?: string }>("/admin/invitations", { method: "POST", body: { email, role_id } }),
  updateUser: (id: string, patch: { role_id?: string; status?: "active" | "suspended" }) =>
    request<{ ok: boolean }>(`/admin/users/${encodeURIComponent(id)}`, { method: "PATCH", body: patch }),
  apiKeys: () => request<ApiKey[]>("/admin/api-keys"),
  createApiKey: (label: string, opts: { expires_in_days?: number; rate_limit_per_min?: number } = {}) =>
    request<{ api_key: string; prefix: string; message: string }>("/admin/api-keys", { method: "POST", body: { ...(label ? { label } : {}), ...opts } }),
  rotateApiKey: (prefix: string) =>
    request<{ api_key: string; prefix: string; old_key_expires_at: string; message: string }>(`/admin/api-keys/${encodeURIComponent(prefix)}/rotate`, { method: "POST" }),
  revokeApiKey: (prefix: string) => request<{ revoked: string }>(`/admin/api-keys/${encodeURIComponent(prefix)}`, { method: "DELETE" }),
  security: () => request<SecuritySettings>("/admin/security"),
  setSecurity: (patch: SecurityPatch) => request<{ ok: boolean }>("/admin/security", { method: "PUT", body: patch }),
};

// ---- phase 8: effective permissions, reviews, owner access, teams, staff, approvals, exports ----
export const governance = {
  effectiveForUser: (id: string) => request<Effective>(`/admin/users/${encodeURIComponent(id)}/effective-permissions`),
  effectiveForRole: (id: string) => request<Effective>(`/admin/roles/${encodeURIComponent(id)}/effective`),
  /** `scope` "tenant" reviews the organization's people, "platform" the platform's own staff. */
  reviews: (scope: "tenant" | "platform") => {
    const base = scope === "tenant" ? "/admin/access-reviews" : "/platform/access-reviews";
    return {
      list: () => request<ReviewSummary[]>(base),
      open: (title?: string) => request<{ id: string; items: number }>(base, { method: "POST", body: title ? { title } : {} }),
      get: (id: string) => request<ReviewDetail>(`${base}/${encodeURIComponent(id)}`),
      decide: (id: string, uid: string, body: { decision: "keep" | "change" | "remove"; new_role_id?: string; note?: string }) =>
        request<{ decision: string }>(`${base}/${encodeURIComponent(id)}/members/${encodeURIComponent(uid)}`, { method: "PUT", body }),
      signOff: (id: string) => request<{ status: string; keep: number; change: number; remove: number }>(`${base}/${encodeURIComponent(id)}/sign-off`, { method: "POST" }),
    };
  },
  exportAudit: (format: "json" | "csv") => request<DownloadLink>("/admin/audit/export", { method: "POST", body: { format } }),
  exportData: () => request<DownloadLink>("/admin/data-export", { method: "POST" }),
  /** Fetch a one-time download link while signed in; the file text comes back once. */
  download: (path: string) => request<string>(path, { asText: true }),
};

export const ownerAccess = {
  /** The organization's side: who asked to enter, and who is inside. */
  requests: () => request<AccessRequest[]>("/admin/access-requests"),
  approve: (id: string) => request<{ status: string }>(`/admin/access-requests/${encodeURIComponent(id)}/approve`, { method: "POST" }),
  deny: (id: string, reason: string) => request<{ status: string }>(`/admin/access-requests/${encodeURIComponent(id)}/deny`, { method: "POST", body: { reason } }),
  endForTenant: (id: string) => request<{ ended: string }>(`/admin/access-requests/${encodeURIComponent(id)}`, { method: "DELETE" }),
  /** The platform's side. */
  sessions: () => request<AccessRequest[]>("/platform/access"),
  request: (orgId: string, reason: string) =>
    request<{ session_id: string; status: string }>(`/platform/orgs/${encodeURIComponent(orgId)}/access`, { method: "POST", body: { reason } }),
  extend: (id: string) => request<{ until: string }>(`/platform/access/${encodeURIComponent(id)}/extend`, { method: "POST" }),
  end: (id: string) => request<{ ended: string }>(`/platform/access/${encodeURIComponent(id)}`, { method: "DELETE" }),
};

export const teamsApi = {
  list: () => request<Team[]>("/admin/teams"),
  create: (name: string) => request<{ id: string }>("/admin/teams", { method: "POST", body: { name } }),
  rename: (id: string, name: string) => request<{ ok: boolean }>(`/admin/teams/${encodeURIComponent(id)}`, { method: "PUT", body: { name } }),
  remove: (id: string) => request<{ deleted: string }>(`/admin/teams/${encodeURIComponent(id)}`, { method: "DELETE" }),
  get: (id: string) => request<TeamDetail>(`/admin/teams/${encodeURIComponent(id)}`),
  setMembers: (id: string, user_ids: string[]) =>
    request<{ members: number }>(`/admin/teams/${encodeURIComponent(id)}/members`, { method: "PUT", body: { user_ids } }),
  mine: () => request<{ teams: { id: string; name: string; open_alerts: number }[] }>("/me/teams"),
};

export const staff = {
  users: () => request<StaffUser[]>("/platform/users"),
  roles: () => request<{ roles: { id: string; name: string; system: boolean; perms: string[] }[] }>("/platform/roles"),
  invite: (email: string, role_id: string) =>
    request<{ invited: string; dev_link?: string }>("/platform/invitations", { method: "POST", body: { email, role_id } }),
  update: (id: string, patch: { role_id?: string; status?: "active" | "suspended" }) =>
    request<{ ok?: boolean; approval_id?: string; status?: string }>(`/platform/users/${encodeURIComponent(id)}`, { method: "PATCH", body: patch }),
};

export const approvals = {
  list: () => request<Approval[]>("/platform/approvals"),
  approve: (id: string) => request<{ status: string }>(`/platform/approvals/${encodeURIComponent(id)}/approve`, { method: "POST" }),
  deny: (id: string, reason: string) => request<{ status: string }>(`/platform/approvals/${encodeURIComponent(id)}/deny`, { method: "POST", body: { reason } }),
};

export const tenantAdmin = {
  create: (b: { legal_name: string; business_type: string; registration: string; admin_email: string; plan: string }) =>
    request<{ id: string; status: string; dev_link?: string }>("/platform/orgs", { method: "POST", body: b }),
  setStatus: (id: string, status: "active" | "suspended", reason: string) =>
    request<{ status: string }>(`/platform/orgs/${encodeURIComponent(id)}/status`, { method: "POST", body: { status, reason } }),
  requestDelete: (id: string, reason: string) =>
    request<{ approval_id: string }>(`/platform/orgs/${encodeURIComponent(id)}/delete`, { method: "POST", body: { reason } }),
};
