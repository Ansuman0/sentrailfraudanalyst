/**
 * Organization permissions a custom role can hold, with the wording from docs/permissions.md. The API is the source of truth
 * (it rejects anything else); this list only gives checkboxes their labels. A permission the API returns that isn't
 * listed here is still shown, under its raw id. `sensitive` = asks for a fresh second factor (docs/permissions.md, step-up).
 */
export const ORG_PERMISSIONS: { id: string; label: string; sensitive?: boolean }[] = [
  { id: "cases.view", label: "View alerts, cases and transfers" },
  { id: "cases.restricted.view", label: "View restricted (need-to-know) cases" },
  { id: "cases.decide", label: "Close alerts, request info" },
  { id: "str.draft", label: "Run AI investigation and draft STRs" },
  { id: "str.approve", label: "Approve and file STRs", sensitive: true },
  { id: "screening.override", label: "Release or block held transfers", sensitive: true },
  { id: "wallet.trace", label: "Trace wallets" },
  { id: "policy.edit", label: "Change screening policy", sensitive: true },
  { id: "data.export", label: "Export case data", sensitive: true },
  { id: "audit.view", label: "View audit log" },
  { id: "audit.export", label: "Export or stream the audit log", sensitive: true },
  { id: "users.manage", label: "Invite and manage users" },
  { id: "users.pii.reveal", label: "Reveal a person's email" },
  { id: "security.manage", label: "Change security settings and sign-in", sensitive: true },
  { id: "apikeys.manage", label: "Manage API keys", sensitive: true },
  { id: "roles.manage", label: "Edit roles and permissions" },
  { id: "features.manage", label: "Turn features on or off" },
  { id: "access.review", label: "Run and sign off access reviews" },
  { id: "teams.manage", label: "Manage teams and queues" },
];

export const permissionLabel = (id: string) => ORG_PERMISSIONS.find((p) => p.id === id)?.label ?? id;
