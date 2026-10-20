import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { RequireAuth, RequirePerm } from "./components/RequireAuth";
import { useAuth } from "./hooks/useAuth";
import { Account } from "./pages/Account";
import { Alerts } from "./pages/Alerts";
import { ApiKeys } from "./pages/ApiKeys";
import { Audit } from "./pages/Audit";
import { CaseView } from "./pages/CaseView";
import { Features } from "./pages/Features";
import { Join } from "./pages/Join";
import { Organizations } from "./pages/Organizations";
import { Plans } from "./pages/Plans";
import { PlatformSecurity } from "./pages/PlatformSecurity";
import { Policy } from "./pages/Policy";
import { Roles } from "./pages/Roles";
import { Search } from "./pages/Search";
import { Security } from "./pages/Security";
import { SignedOut, SignIn } from "./pages/SignIn";
import { Sso } from "./pages/Sso";
import { TwoFactorSetup } from "./pages/TwoFactorSetup";
import { Users } from "./pages/Users";
import { WalletTrace } from "./pages/WalletTrace";

/** The first screen this role can use: analysts land on alerts, platform staff on organizations. */
function Home() {
  const { can, canAny } = useAuth();
  if (can("cases.view")) return <Navigate to="/alerts" replace />;
  if (canAny("orgs.manage", "platform.support")) return <Navigate to="/organizations" replace />;
  if (canAny("audit.view", "platform.audit.view")) return <Navigate to="/audit" replace />;
  if (can("users.manage")) return <Navigate to="/users" replace />;
  return <Navigate to="/account" replace />;
}

export function App() {
  const { can, canAny, hasFeature } = useAuth();
  return (
    <Routes>
      <Route path="/signin" element={<SignIn />} />
      <Route path="/signed-out" element={<SignedOut />} />
      <Route path="/join" element={<Join />} />
      <Route path="/setup-2fa" element={<RequireAuth><TwoFactorSetup /></RequireAuth>} />
      <Route element={<RequireAuth><Layout /></RequireAuth>}>
        <Route index element={<Home />} />
        <Route path="alerts" element={<RequirePerm allowed={can("cases.view") && hasFeature("alerts")}><Alerts /></RequirePerm>} />
        <Route path="cases/:id" element={<RequirePerm allowed={can("cases.view")}><CaseView /></RequirePerm>} />
        <Route path="search" element={<RequirePerm allowed={can("cases.view")}><Search /></RequirePerm>} />
        <Route path="trace" element={<RequirePerm allowed={can("wallet.trace") && hasFeature("trace")}><WalletTrace /></RequirePerm>} />
        <Route path="policy" element={<RequirePerm allowed={can("cases.view")}><Policy /></RequirePerm>} />
        <Route path="audit" element={<RequirePerm allowed={canAny("audit.view", "platform.audit.view")}><Audit /></RequirePerm>} />
        <Route path="users" element={<RequirePerm allowed={can("users.manage")}><Users /></RequirePerm>} />
        <Route path="sso" element={<RequirePerm allowed={can("users.manage")}><Sso /></RequirePerm>} />
        <Route path="features" element={<RequirePerm allowed={can("features.manage")}><Features /></RequirePerm>} />
        <Route path="roles" element={<RequirePerm allowed={can("roles.manage")}><Roles /></RequirePerm>} />
        <Route path="api-keys" element={<RequirePerm allowed={can("users.manage") && hasFeature("screening")}><ApiKeys /></RequirePerm>} />
        <Route path="security" element={<RequirePerm allowed={can("users.manage")}><Security /></RequirePerm>} />
        <Route path="organizations" element={<RequirePerm allowed={canAny("orgs.manage", "platform.support")}><Organizations /></RequirePerm>} />
        <Route path="platform-security" element={<RequirePerm allowed={can("platform.security.manage")}><PlatformSecurity /></RequirePerm>} />
        <Route path="plans" element={<RequirePerm allowed={canAny("platform.plans.manage", "orgs.manage")}><Plans /></RequirePerm>} />
        <Route path="account" element={<Account />} />
        <Route path="*" element={<><h1>Page not found</h1><p className="sub">That address doesn't match any screen.</p></>} />
      </Route>
    </Routes>
  );
}
