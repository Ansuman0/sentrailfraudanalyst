# API

Base `http://localhost:8000`. Interactive docs at `/docs` only when `ENV=dev`. Human-session routes use
`Authorization: Bearer <access token>`; machine screening uses `Authorization: Bearer sk_live_…` (API key, rate-limited per key).
Errors are FastAPI `{"detail": "<message for end users>"}`. The server enforces every permission ([ROLES.md](ROLES.md)).
The README has the screening request example and alert lifecycle.

| Area | Routes |
|---|---|
| Health | `GET /healthz`, `GET /readyz` (DB + sanctions list status) |
| Auth | `POST /auth/discover`, `/auth/login`, `/auth/mfa`, `/auth/refresh`, `/auth/logout`; `GET /auth/oidc/login`, `/auth/oidc/callback`, `/auth/oidc/logout`; `POST /invitations/accept` |
| Me | `GET /me`; `POST /me/mfa/setup`, `/me/mfa/confirm`; `GET /me/sessions`; `POST /me/sessions/end-others`; `DELETE /me/sessions/{family_id}` |
| Screening | `POST /screen` (API key), `GET /screenings/{sid}`, `POST /screenings/{sid}/override`, `POST /upload` |
| Alerts and cases | `GET /alerts`; `GET /cases/{alert_id}`; `POST …/assign`, `…/decision`, `…/investigate`, `…/str/submit`, `…/str/approve`; `GET …/export` |
| Search, tracing, policy | `GET /search`, `GET /wallets/{address}/trace`, `GET/PUT /policy` |
| Tenant admin and other roles (by permission, see [route-permissions.md](route-permissions.md)) | `/admin/users`, `/admin/roles`, `/admin/invitations`, `/admin/api-keys`, `/admin/features`, `/admin/security`, `/admin/sso`, `/admin/audit`, `/admin/audit/verify`, `…/reset-mfa`, `…/reveal-email` |
| Platform console | `/platform/orgs`, `/platform/plans`, `/platform/roles`, `/platform/users`, `/platform/security`, `/platform/invitations` |
| Governance | `/admin/access-reviews*`, `/admin/audit/export`, `/admin/audit/stream`, `/admin/data-export`, `GET /me/exports/{token}`, `/admin/scim/*`, `/admin/teams*`, `/admin/access-requests*`, `/admin/users/{id}/effective-permissions`, `/admin/roles/{id}/effective` |
| SCIM 2.0 (Enterprise, SCIM token) | `/scim/v2/Users`, `/scim/v2/Groups`, `/scim/v2/ServiceProviderConfig` |
| Platform governance | `/platform/access*`, `/platform/approvals*`, `/platform/access-reviews*`, `POST /platform/orgs/{id}/{status,delete,admin,legal-hold,access}` |

This list was taken from the route decorators in `backend/app/main.py` and `backend/app/admin_api.py`; regenerate from `/docs` if routes change.
