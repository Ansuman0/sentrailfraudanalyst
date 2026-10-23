// Shapes returned by the Sentrail API (app/main.py, app/admin_api.py). Only the fields the UI reads.

export type Band = "high" | "medium" | "low";
export type AlertStatus = "open" | "pending_info" | "escalated" | "closed" | "awaiting_approval" | "str_filed";

export interface Tenant {
  id?: string;
  name: string;
  slug: string;
  environment: "production" | "sandbox" | "platform";
  brand_color: string;
}

export interface Me {
  user_id: string;
  name: string | null;
  email: string; // masked by the API
  role: string;
  tenant: Tenant;
  permissions: string[];
  features: string[];
  /** users.mfa_enabled: the person has confirmed an authenticator app (or their sign-in provider handles it). */
  mfa_enabled: boolean;
  /** While two-factor is off: "required" = must set it up now, "optional" = may skip. null once it's on. */
  mfa_setup: "required" | "optional" | null;
  /** This session was signed in with a second factor. */
  session_mfa: boolean;
  /** "tenant" | "platform" | "select" (signed in, tenant not chosen yet: `tenant` is null and there are no permissions). */
  scope?: "tenant" | "platform" | "select";
  selecting?: boolean;
  /** A platform owner working inside this tenant through a time-limited access session (shown as a banner). */
  access_session?: { id: string; expires_at: string; reason: string; extended: boolean } | null;
  /** The break-glass account was just used: the password has to be changed before anything else. */
  must_rotate?: boolean;
  /** Number of passkeys registered, and whether the platform makes this owner register one before anything else. */
  passkeys?: number;
  must_enroll_passkey?: boolean;
  /** Where this person can work (access model v2). The header offers a switcher when there is more than one. */
  tenants?: TenantChoice[];
  /** Teams and queues are switched on for this deployment. */
  teams_enabled?: boolean;
}

export interface TenantChoice {
  id: string | null; // null = the platform console
  name: string;
  slug: string;
  role: string;
  kind?: "tenant" | "platform";
  current?: boolean;
}

export interface Reason {
  source: string;
  text: string;
  share?: number;
}

export interface Alert {
  id: string;
  customer_id: string;
  score: number;
  band: Band;
  reasons: Reason[];
  channel: string;
  status: AlertStatus;
  created_at: string;
  assigned_to: string | null;
  screening_id: string | null;
  /** Need-to-know case: visible only to people with cases.restricted.view or named on the case. */
  restricted?: boolean;
  /** The team queue this alert sits in (teams are optional). */
  team_id?: string | null;
}

export interface Screening {
  id: string;
  customer_id: string;
  direction: "deposit" | "withdrawal";
  address: string;
  amount: number;
  asset: string;
  fiat_value: number | null;
  score: number;
  decision: "release" | "hold" | "block";
  reasons: string[];
  override: "release" | "block" | null;
  override_by: string | null;
  override_reason: string | null;
  override_at: string | null;
  created_at: string;
}

export interface CaseDetail {
  alert: Alert;
  customer_id: string;
  score: number;
  band: Band;
  reasons: Reason[];
  parts?: { rules: number; ml: number; graph: number };
  source: "transaction_history" | "screening";
  screening?: Screening | null;
  transactions: Record<string, string>[];
}

export interface Investigation {
  str_draft: string;
  steps: string[];
  verification: { ok: boolean; unverified: string[]; checked: number };
}

export interface TraceResult {
  address: string;
  network: string;
  summary: {
    inflow: number;
    outflow: number;
    unique_senders: number;
    unique_receivers: number;
    tx_count: number;
    first_seen: string | null;
    last_seen: string | null;
  } | null;
  nodes: { id: string; hop: number; flag: { label: string; source: string } | null }[];
  edges: { from: string; to: string; amount: number; hop: number }[];
  risk_hits: { address: string; hop: number; label: string; source: string }[];
  exposure_score: number;
  explanation: string;
}

export interface SearchResult {
  kind: string;
  network?: string;
  next?: string;
  customers?: string[];
  result?: { customer_id: string; score: number; band: Band; reasons: Reason[] };
  note?: string;
}

export interface Policy {
  hold_at: number;
  block_at: number;
  travel_rule_threshold: number;
  self_hosted_proof_above: number;
  always_block_sanctions: boolean;
}

export interface AuditEvent {
  seq: number;
  at: string;
  actor: string | null;
  role: string | null;
  action: string;
  target: string | null;
  detail: Record<string, unknown> | null;
  ip: string | null;
}

export interface Session {
  id: string;
  device: string;
  ip: string | null;
  method: string;
  last_active: string;
  current: boolean;
}

export interface Organization {
  id: string;
  legal_name: string;
  business_type: string;
  registration: string;
  data_region: string;
  plan: string;
  status: string;
  users: number;
  features: string[] | null;
}

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
}

/** POST /auth/login: a code is needed (two-factor on), or a password-only session (two-factor not set up yet). */
export type LoginResponse =
  | { mfa_token: string; next: string; methods?: ("totp" | "passkey")[]; passkey_options?: Record<string, any> }
  | (TokenResponse & { mfa_enabled: false; route?: SignInRoute; tenants?: TenantChoice[] });

/** Where a fresh sign-in lands: the console, one tenant, the tenant picker, or the no-access page. */
export type SignInRoute = "console" | "tenant" | "picker" | "no_access";

/** GET /platform/security. PUT replaces the whole object: omitted fields reset to the API's defaults. */
export interface PlatformSecurity {
  min_password_len_floor: number;
  max_idle_timeout_min: number;
  max_session_hours: number;
  retention_years_floor: number;
  passkeys_allowed: boolean;
  platform_staff_passkey_only: boolean;
  allowed_regions: string[];
  mfa: string;
}

export interface Plan {
  key: string;
  name: string;
  features: string[];
  max_users: number | null;
  organizations: number;
}

// ---- organization administration (/admin/*) ----
export interface AdminUser {
  id: string;
  name: string | null;
  email: string; // masked by the API
  role: string;
  status: "invited" | "active" | "suspended";
  mfa: boolean;
  last_login: string | null;
}

export interface RoleSummary {
  id: string;
  name: string;
  system: boolean;
  perms: string[];
  /** The Tenant admin role: always holds every tenant permission and cannot be edited or deleted. */
  locked?: boolean;
}

export interface ApiKey {
  prefix: string;
  label: string | null;
  created_at: string;
  revoked_at: string | null;
  active: boolean;
  expires_at?: string | null;
  last_used_at?: string | null;
  rate_limit_per_min?: number;
}

export interface SecuritySettings {
  mfa_required: boolean;
  sso_enabled: boolean;
  idle_timeout_min: number;
  min_password_len: number;
  ip_allowlist: string[];
  retention_years: number;
  dormant_days: number;
  access_review_days: number;
  export_limit_per_hour: number;
  anomaly_searches_per_hour: number;
  anomaly_exports_per_hour: number;
  alert_new_country: boolean;
  encryption: { algorithm: string; current_key: string; key_manager: string };
}

export interface Passkey {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

// ---- phase 8: governance and administration screens ----
export interface ReviewSummary {
  id: string;
  title: string;
  status: "open" | "signed_off" | "cancelled";
  opened_at: string;
  due_at: string;
  signed_off_at: string | null;
  signed_off_by: string | null;
  overdue: boolean;
  items?: number;
  decided?: number;
}

export interface ReviewMember {
  user_id: string;
  name: string | null;
  email: string | null;
  role: string;
  decision: "keep" | "change" | "remove" | null;
  new_role_id: string | null;
  note: string | null;
  decided_at: string | null;
}

export interface ReviewDetail extends ReviewSummary {
  members: ReviewMember[];
}

export interface AccessRequest {
  id: string;
  tenant_id: string;
  tenant: string;
  owner_user_id: string;
  reason: string;
  status: "requested" | "approved" | "active" | "ended" | "denied";
  requested_at: string;
  started_at: string | null;
  expires_at: string | null;
  extended: boolean;
  ended_at: string | null;
  ended_reason: string | null;
  legal_hold: boolean;
  request_expires_at: string | null;
}

export interface Team {
  id: string;
  name: string;
  members: number;
  open_alerts: number;
}

export interface TeamDetail {
  id: string;
  name: string;
  members: { user_id: string; name: string | null; email: string | null }[];
}

export interface StaffUser {
  id: string;
  name: string | null;
  email: string;
  role: string;
  status: string;
  sign_in: string;
  last_login: string | null;
}

export interface Approval {
  id: string;
  action: string;
  payload: Record<string, unknown>;
  requested_by: string;
  approved_by: string | null;
  status: "pending" | "approved" | "denied" | "expired";
  reason: string | null;
  created_at: string;
  decided_at: string | null;
  expires_at: string;
}

export interface Effective {
  role: string;
  locked: boolean;
  permissions: { key: string; group: string; description: string; step_up: boolean }[];
  features: string[];
  warnings: string[];
}

export interface DownloadLink {
  download_path: string;
  expires_at: string;
  filename: string;
  note: string;
}
