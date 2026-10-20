import { useState, type FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { BandBadge, ErrorBox, PageHeader } from "../components/common";
import { investigate } from "../services/sentrail";

// Every lookup is audited with a reason (the API requires one). The reason is only recorded, never used to filter results; "All" covers any of them.
const REASONS = ["All", "Alert investigation", "Law enforcement request", "Customer complaint", "Periodic review"];

export function Search() {
  const [q, setQ] = useState("");
  const [reason, setReason] = useState("");
  const search = useMutation({ mutationFn: () => investigate.search(q.trim(), reason) });
  const onSubmit = (e: FormEvent) => { e.preventDefault(); search.mutate(); };
  const r = search.data;

  return (
    <>
      <PageHeader title="Search" sub="Customer ID, account, card last 4, wallet address or transaction hash. Full card numbers are refused." />
      <form className="form-row" onSubmit={onSubmit}>
        <input type="text" aria-label="Search" maxLength={200} value={q} onChange={(e) => setQ(e.target.value)}
               placeholder="e.g. C-2291, 4821, TQ7m…" />
        <select className="reason" aria-label="Reason for lookup" value={reason} onChange={(e) => setReason(e.target.value)}>
          <option value="">Reason for lookup</option>
          {REASONS.map((x) => <option key={x}>{x}</option>)}
        </select>
        <button className="btn primary" disabled={!q.trim() || !reason || search.isPending}>
          {search.isPending ? "Searching…" : "Search"}
        </button>
      </form>
      <div className="results">
        {search.isError && <ErrorBox error={search.error} />}
        {r && r.kind === "wallet" && (
          <p>That's a {r.network} wallet. <Link to={`/trace?address=${encodeURIComponent(q.trim())}`}>Trace it →</Link></p>
        )}
        {r?.result && (
          <div className="panel">
            <h2><span className="mono">{r.result.customer_id}</span> · score {r.result.score} <BandBadge band={r.result.band} /></h2>
            {r.result.reasons.slice(0, 5).map((x, i) => <div key={i} className="reason"><span>{x.text}</span><span className="src">{x.source}</span></div>)}
          </div>
        )}
        {r?.customers && (r.customers.length ? (
          <p>Matching customers: {r.customers.map((c) => <span key={c} className="mono chip-inline">{c}</span>)}</p>
        ) : <p className="muted">{r.note ?? "No matches."}</p>)}
      </div>
    </>
  );
}
