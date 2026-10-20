import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";
import { Logo } from "./Logo";

interface NavItem {
  to: string;
  label: string;
  show: boolean;
}

/** Navigation only hides what a role can't use. The API enforces every permission on its own. */
export function Layout() {
  const { me, can, canAny, hasFeature, signOut } = useAuth();
  if (!me) return null;
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
        { to: "/sso", label: "Company sign-in", show: can("users.manage") },
        { to: "/features", label: "Features", show: can("features.manage") },
        { to: "/roles", label: "Roles", show: can("roles.manage") },
        { to: "/api-keys", label: "API keys", show: can("users.manage") && hasFeature("screening") },
        { to: "/security", label: "Security settings", show: can("users.manage") },
      ],
    },
    {
      title: "Tenants",
      items: [
        { to: "/organizations", label: "Organizations", show: canAny("orgs.manage", "platform.support") },
        { to: "/platform-security", label: "Security baseline", show: can("platform.security.manage") },
        { to: "/plans", label: "Plans", show: canAny("platform.plans.manage", "orgs.manage") },
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
        <Outlet />
      </main>
    </div>
  );
}
