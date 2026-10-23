import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";
import { accessSession } from "../services/sentrail";
import { Logo } from "./Logo";

interface NavItem {
  to: string;
  label: string;
  show: boolean;
}

/** Navigation only hides what a role can't use. The API enforces every permission on its own. */
export function Layout() {
  const { me, can, canAny, hasFeature, signOut, switchTenant, preview, stopPreview } = useAuth();
  const navigate = useNavigate();
  if (!me || me.selecting) return null;
  const t = me.tenant;
  const groups: { title: string; items: NavItem[] }[] = [
    {
      title: "Monitor",
      items: [{ to: "/alerts", label: "Alerts", show: can("cases.view") && hasFeature("alerts") }],
    },
    {
      title: "Investigate",
      items: [
        { to: "/search", label: "Search", show: can("cases.view") },
        { to: "/trace", label: "Wallet trace", show: can("wallet.trace") && hasFeature("trace") },
      ],
    },
    {
      title: "Govern",
      items: [
        { to: "/policy", label: "Screening policy", show: can("cases.view") },
        { to: "/audit", label: "Audit log", show: canAny("audit.view", "platform.audit.view") },
      ],
    },
    {
      title: "Administer",
      items: [
        { to: "/users", label: "Users", show: can("users.manage") },
        { to: "/sso", label: "Company sign-in", show: can("security.manage") },
        { to: "/features", label: "Features", show: can("features.manage") },
        { to: "/roles", label: "Roles", show: can("roles.manage") },
        { to: "/api-keys", label: "API keys", show: can("apikeys.manage") && hasFeature("screening") },
        { to: "/security", label: "Security settings", show: can("security.manage") },
        { to: "/access-reviews", label: "Access reviews", show: can("access.review") },
        { to: "/owner-access", label: "Platform access requests", show: can("security.manage") },
        { to: "/teams", label: "Teams", show: can("teams.manage") && !!me.teams_enabled },
      ],
    },
    {
      title: "Tenants",
      items: [
        { to: "/organizations", label: "Organizations", show: canAny("platform.tenants.manage", "platform.support") },
        { to: "/platform-security", label: "Security baseline", show: can("platform.security.manage") },
        { to: "/plans", label: "Plans", show: canAny("platform.plans.manage", "platform.tenants.manage") },
      ],
    },
    {
      title: "Platform team",
      items: [
        { to: "/staff", label: "Staff", show: can("platform.users.manage") },
        { to: "/approvals", label: "Approvals", show: canAny("platform.owners.manage", "platform.security.manage", "platform.tenants.delete", "platform.tenants.manage") },
        { to: "/access-sessions", label: "Tenant access sessions", show: canAny("platform.tenant.access", "platform.audit.view") },
        { to: "/staff-reviews", label: "Staff access review", show: can("platform.owners.manage") },
      ],
    },
  ];
  const envClass = t.environment === "production" ? "prod" : t.environment;

  return (
    <div className={`app${t.environment === "sandbox" ? " sandbox" : ""}`}>
      <nav className="rail" aria-label="Main">
        <div className="brand">
          <Logo />
          <span>Sentrail</span>
        </div>
        <div className="tenant" aria-label="Current organization">
          <span className="av" style={{ background: t.brand_color }}>
            {t.name.split(/\s+/).map((w) => w[0]).join("").slice(0, 2).toUpperCase()}
          </span>
          <div>
            <div className="tn">{t.name}</div>
            <div className="tm">
              <span className={`env ${envClass}`}>{t.environment}</span>
            </div>
          </div>
        </div>
        {(me.tenants ?? []).length > 1 && (
          <div className="switcher">
            <label htmlFor="switch-tenant">Switch tenant</label>
            <select id="switch-tenant" value={(me.tenants ?? []).find((x) => x.current)?.id ?? ""}
                    onChange={(e) => { void switchTenant(e.target.value || null).then(() => navigate("/")); }}>
              {(me.tenants ?? []).map((x) => <option key={x.id ?? "platform"} value={x.id ?? ""}>{x.name}</option>)}
            </select>
          </div>
        )}
        {groups.map((g) => {
          const items = g.items.filter((i) => i.show);
          if (!items.length) return null;
          return (
            <div key={g.title} className="navsection">
              <p className="navgroup">{g.title}</p>
              {items.map((i) => (
                <NavLink key={i.to} to={i.to} className="navlink">
                  {i.label}
                </NavLink>
              ))}
            </div>
          );
        })}
        <div className="who">
          <strong>{me.name ?? me.email}</strong>
          <span className="rolechip">{me.role}</span>
          <div className="mono whoemail">{me.email}</div>
          <div className="whoactions">
            <NavLink to="/account" className="linkbtn">
              My account
            </NavLink>
            <button type="button" className="linkbtn" onClick={() => void signOut()}>
              Sign out
            </button>
          </div>
        </div>
      </nav>
      <main className="page">
        {preview && (
          <div className="accessbanner" role="status">
            <div>
              <b>Previewing as {preview.role}.</b> The screens show what this role would see. The server still applies your own permissions to everything you do.
            </div>
            <button type="button" className="btn" onClick={stopPreview}>Exit preview</button>
          </div>
        )}
        {me.access_session && (
          <div className="accessbanner" role="status">
            <div>
              <b>Platform owner access.</b> You are inside {t.name} until {new Date(me.access_session.expires_at).toLocaleTimeString()}.
              Everything you do is recorded in this organization's audit log and the platform's.
              <span className="muted"> Reason: {me.access_session.reason}</span>
            </div>
            <button type="button" className="btn" onClick={() => void accessSession.end().finally(() => void switchTenant(null).then(() => navigate("/")))}>
              End access
            </button>
          </div>
        )}
        <Outlet />
      </main>
    </div>
  );
}
