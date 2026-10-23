import { useQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { BandBadge, Empty, ErrorBox, Loading, PageHeader, Score } from "../components/common";
import { useAuth } from "../hooks/useAuth";
import { cases, teamsApi } from "../services/sentrail";
import type { AlertStatus, Band } from "../types/api";
import { fmtDateTime, humanize } from "../utils/format";

const STATUSES: AlertStatus[] = ["open", "pending_info", "escalated", "awaiting_approval", "closed", "str_filed"];
const BANDS: (Band | "all")[] = ["all", "high", "medium", "low"];

export function Alerts() {
  const [params, setParams] = useSearchParams();
  const status = (STATUSES.includes(params.get("status") as AlertStatus) ? params.get("status") : "open") as AlertStatus;
  const bandParam = params.get("band");
  const band = (BANDS.includes(bandParam as Band) ? bandParam : "all") as Band | "all";
  const navigate = useNavigate();
  const { me } = useAuth();
  const mine = useQuery({ queryKey: ["my-teams"], queryFn: teamsApi.mine, enabled: !!me?.teams_enabled });
  const team = params.get("team") ?? "";
  const q = useQuery({
    queryKey: ["alerts", status, band, team],
    queryFn: () => cases.alerts(status, band === "all" ? undefined : band, team || undefined),
  });

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    setParams(next, { replace: true });
  };

  return (
    <>
      <PageHeader title="Alerts" sub="Highest risk first. Open an alert to see why it scored and record a decision." />
      <div className="chips" role="group" aria-label="Status">
        {STATUSES.map((s) => (
          <button key={s} className="chip" aria-pressed={s === status} onClick={() => set("status", s)}>
            {humanize(s)}
          </button>
        ))}
      </div>
      <div className="chips" role="group" aria-label="Risk band">
        {BANDS.map((b) => (
          <button key={b} className="chip" aria-pressed={b === band} onClick={() => set("band", b)}>
            {b === "all" ? "All bands" : b}
          </button>
        ))}
      </div>
      {me?.teams_enabled && (mine.data?.teams.length ?? 0) > 0 && (
        <div className="chips" role="group" aria-label="Queue">
          <button className="chip" aria-pressed={!team} onClick={() => set("team", "")}>All alerts</button>
          {mine.data?.teams.map((t) => (
            <button key={t.id} className="chip" aria-pressed={team === t.id} onClick={() => set("team", t.id)}>{t.name} ({t.open_alerts})</button>
          ))}
        </div>
      )}
      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorBox error={q.error} title="Alerts couldn't be loaded" />
      ) : q.data.length === 0 ? (
        <Empty>No {humanize(status)} alerts{band !== "all" ? ` in the ${band} band` : ""}.</Empty>
      ) : (
        <div className="tablewrap">
          <table>
            <thead>
              <tr><th>Alert</th><th>Customer</th><th>Score</th><th>Band</th><th>Main reason</th><th>Channel</th><th>Raised</th></tr>
            </thead>
            <tbody>
              {q.data.map((a) => (
                <tr key={a.id} className="click" tabIndex={0}
                    onClick={() => navigate(`/cases/${encodeURIComponent(a.id)}`)}
                    onKeyDown={(e) => e.key === "Enter" && navigate(`/cases/${encodeURIComponent(a.id)}`)}>
                  <td className="mono">{a.id}</td>
                  <td className="mono">{a.customer_id}</td>
                  <td><Score score={a.score} band={a.band} /></td>
                  <td><BandBadge band={a.band} /></td>
                  <td>{a.reasons[0]?.text ?? "—"}</td>
                  <td>{a.channel.split(",").map((c) => <span key={c} className={`ch ${c}`}>{c}</span>)}</td>
                  <td className="muted">{fmtDateTime(a.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
