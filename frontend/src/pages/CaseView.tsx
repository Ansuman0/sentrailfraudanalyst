import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { BandBadge, ErrorBox, Loading, StatusBadge } from "../components/common";
import { useAuth } from "../hooks/useAuth";
import { cases } from "../services/sentrail";
import type { CaseDetail } from "../types/api";
import { fmtDateTime, fmtNumber } from "../utils/format";

const DECIDABLE = ["open", "pending_info"];
const STR_SUBMITTABLE = ["escalated", "awaiting_approval"];

export function CaseView() {
  const { id = "" } = useParams();
  const q = useQuery({ queryKey: ["case", id], queryFn: () => cases.get(id) });

  if (q.isPending) return <Loading label="Loading case…" />;
  if (q.isError) return (<><BackLink /><ErrorBox error={q.error} title="This case couldn't be opened" /></>);
  const c = q.data;
  return (
    <>
      <BackLink />
      <div className="casehead">
        <div>
          <h1>Alert <span className="mono">{c.alert.id}</span></h1>
          <div className="facts">
            <div><b className="mono">{c.alert.customer_id}</b>Customer</div>
            <div><b><StatusBadge status={c.alert.status} /></b>Status</div>
            <div><b>{fmtDateTime(c.alert.created_at)}</b>Raised</div>
            <div><b>{c.source === "transaction_history" ? "Transaction history" : c.screening ? "Real-time screening" : "Alert record only"}</b>Scored from</div>
          </div>
        </div>
        <div className="dial">
          <span className="num">{c.score}</span>
          <BandBadge band={c.band} />
        </div>
      </div>
      <div className="grid g2">
        <section className="panel">
          <h2>Why it scored</h2>
          {c.reasons.length === 0 ? <p className="muted">No reasons recorded.</p> : c.reasons.map((r, i) => (
            <div key={i} className="reason">
              <span>{r.text}</span>
              {r.share != null && <span className="muted">{Math.round(r.share * 100)}%</span>}
              <span className="src">{r.source}</span>
            </div>
          ))}
          {c.parts && (
            <div className="parts">
              {(["rules", "ml", "graph"] as const).map((k) => (
                <div key={k} className="part">
                  {k === "ml" ? "Model" : k === "graph" ? "Network" : "Rules"}
                  <b>{c.parts![k]}</b>
                  <div className="bar"><span style={{ width: `${c.parts![k]}%` }} /></div>
                </div>
              ))}
            </div>
          )}
        </section>
        {c.screening ? <ScreeningPanel c={c} /> : <Transactions c={c} />}
      </div>
      <Workflow c={c} />
    </>
  );
}

function BackLink() {
  return <Link className="backlink" to="/alerts">← Alerts</Link>;
}

function ScreeningPanel({ c }: { c: CaseDetail }) {
  const s = c.screening!;
  return (
    <section className="panel">
      <h2>Screened transfer</h2>
      <div className="keycard">
        <div><b className={`dec ${s.decision}`}>{s.decision}</b>Engine decision</div>
        <div><b>{s.direction}</b>Direction</div>
        <div><b>{fmtNumber(s.amount, 8)} {s.asset}</b>Amount</div>
        <div><b>{fmtNumber(s.fiat_value, 2)}</b>Fiat value</div>
      </div>
      <p className="mono wrap">{s.address}</p>
      {s.override && <p>Analyst chose to <b>{s.override}</b>: {s.override_reason}</p>}
    </section>
  );
}

function Transactions({ c }: { c: CaseDetail }) {
  return (
    <section className="panel">
      <h2>Recent activity</h2>
      {c.transactions.length === 0 ? <p className="muted">No transactions loaded for this customer.</p> : (
        <div className="tablewrap">
          <table>
            <thead><tr><th>When</th><th>Direction</th><th>Channel</th><th>Amount</th><th>Counterparty</th></tr></thead>
            <tbody>
              {c.transactions.slice(0, 25).map((t, i) => (
                <tr key={i}>
                  <td className="muted">{t.timestamp}</td><td>{t.direction}</td><td>{t.channel}</td>
                  <td>{t.amount} {t.currency}</td><td className="mono">{t.counterparty_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function Workflow({ c }: { c: CaseDetail }) {
  const { can, hasFeature, me } = useAuth();
  const mfa = me?.session_mfa ?? false;
  const qc = useQueryClient();
  const id = c.alert.id;
  const status = c.alert.status;
  const refresh = () => Promise.all([qc.invalidateQueries({ queryKey: ["case", id] }), qc.invalidateQueries({ queryKey: ["alerts"] })]);

  const [decision, setDecision] = useState<"false_positive" | "request_info" | "escalate">("escalate");
  const [reason, setReason] = useState("");
  const decide = useMutation({ mutationFn: () => cases.decide(id, decision, reason.trim()), onSuccess: () => { setReason(""); return refresh(); } });

  const [strText, setStrText] = useState("");
  const investigate = useMutation({ mutationFn: () => cases.investigate(id), onSuccess: (r) => setStrText(r.str_draft) });
  const submit = useMutation({ mutationFn: () => cases.submitStr(id, strText.trim()), onSuccess: refresh });
  const approve = useMutation({ mutationFn: () => cases.approveStr(id), onSuccess: refresh });

  const canDecide = can("cases.decide") && DECIDABLE.includes(status);
  const canDraft = can("str.draft") && STR_SUBMITTABLE.includes(status);
  const canInvestigate = can("str.draft") && hasFeature("ai") && !["closed", "str_filed"].includes(status);
  const canApprove = can("str.approve") && status === "awaiting_approval";
  if (!canDecide && !canDraft && !canApprove && !canInvestigate) return null;

  const onDecide = (e: FormEvent) => { e.preventDefault(); decide.mutate(); };

  return (
    <div className="grid g2 workflow">
      {canDecide && (
        <form className="panel" onSubmit={onDecide}>
          <h2>Record decision</h2>
          <div className="field">
            <label htmlFor="decision">Decision</label>
            <select id="decision" value={decision} onChange={(e) => setDecision(e.target.value as typeof decision)}>
              <option value="escalate">Escalate for an STR</option>
              <option value="request_info">Request information from the customer</option>
              <option value="false_positive">Close as false positive</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor="reason">Reason (saved to the audit log)</label>
            <textarea id="reason" rows={3} minLength={5} maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} />
            <small>At least 5 characters.</small>
          </div>
          {decide.isError && <ErrorBox error={decide.error} />}
          <div className="actions">
            <button className="btn primary" disabled={decide.isPending || reason.trim().length < 5}>
              {decide.isPending ? "Saving…" : "Save decision"}
            </button>
          </div>
        </form>
      )}
      {(canDraft || canInvestigate) && (
        <section className="panel">
          <h2>Suspicious transaction report <span className="draftnote">Analyst reviews every word</span></h2>
          {canInvestigate && (
            <button className="btn" disabled={investigate.isPending} onClick={() => investigate.mutate()}>
              {investigate.isPending ? "Drafting with the local model…" : "Draft with AI"}
            </button>
          )}
          {investigate.isError && <ErrorBox error={investigate.error} title="The AI draft couldn't be created" />}
          {investigate.data && (
            investigate.data.verification.ok
              ? <p className="verified">✓ Every figure in the draft matches the case facts</p>
              : <div className="err">These figures don't match the records: {investigate.data.verification.unverified.join(", ")}</div>
          )}
          {canDraft && (
            <>
              <div className="str-sec">
                <label htmlFor="strtext">Final text</label>
                <textarea id="strtext" rows={8} minLength={50} maxLength={20000} value={strText} onChange={(e) => setStrText(e.target.value)} />
                <small className="muted">At least 50 characters. A second officer must approve it.</small>
              </div>
              {submit.isError && <ErrorBox error={submit.error} />}
              <div className="actions">
                <button className="btn primary" disabled={submit.isPending || strText.trim().length < 50} onClick={() => submit.mutate()}>
                  {submit.isPending ? "Submitting…" : "Submit for approval"}
                </button>
              </div>
            </>
          )}
          {!canDraft && canInvestigate && <p className="muted">Escalate the alert to submit an STR.</p>}
        </section>
      )}
      {canApprove && (
        <section className="panel">
          <h2>Approve STR</h2>
          <p className="sub">Four-eyes rule: the officer who submitted the STR can't approve it.</p>
          {approve.isError && <ErrorBox error={approve.error} />}
          {mfa ? (
            <button className="btn primary" disabled={approve.isPending} onClick={() => approve.mutate()}>
              {approve.isPending ? "Approving…" : "Approve and file"}
            </button>
          ) : <p className="muted">Turn on two-factor authentication (My account) to approve STRs.</p>}
        </section>
      )}
    </div>
  );
}
