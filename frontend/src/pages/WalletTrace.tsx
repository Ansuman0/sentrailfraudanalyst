import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { ErrorBox, Loading, PageHeader } from "../components/common";
import { investigate } from "../services/sentrail";
import { fmtDateTime, fmtNumber, shorten } from "../utils/format";

export function WalletTrace() {
  const [params, setParams] = useSearchParams();
  const address = params.get("address") ?? "";
  const hops = Math.min(3, Math.max(0, Number(params.get("hops") ?? 2) || 0));
  const [input, setInput] = useState(address);
  const [hopInput, setHopInput] = useState(hops);
  const q = useQuery({
    queryKey: ["trace", address, hops],
    queryFn: () => investigate.trace(address, hops),
    enabled: !!address,
    staleTime: 5 * 60_000, // chain lookups use free API quotas; don't repeat them on every focus
  });
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    setParams({ address: input.trim(), hops: String(hopInput) });
  };

  return (
    <>
      <PageHeader title="Wallet trace" sub="Follow the money from one wallet and check every wallet on the way against sanctions and blocklists." />
      <form className="form-row" onSubmit={onSubmit}>
        <input type="text" aria-label="Wallet address" maxLength={100} value={input} onChange={(e) => setInput(e.target.value)}
               placeholder="TRON, Ethereum or Bitcoin address" />
        <select className="reason" aria-label="Hops" value={hopInput} onChange={(e) => setHopInput(Number(e.target.value))}>
          {[0, 1, 2, 3].map((h) => <option key={h} value={h}>{h} hop{h === 1 ? "" : "s"}</option>)}
        </select>
        <button className="btn primary" disabled={!input.trim()}>Trace</button>
      </form>
      <div className="results">
        {q.isFetching && <Loading label="Reading the chain…" />}
        {q.isError && <ErrorBox error={q.error} title="The trace couldn't be completed" />}
        {q.data && (
          <>
            <div className={`alertbox ${q.data.risk_hits.length ? "" : "clear"}`}>
              <b>Exposure {q.data.exposure_score}/100.</b> {q.data.explanation}
            </div>
            {q.data.summary && (
              <div className="stats">
                <div className="stat"><b>{fmtNumber(q.data.summary.inflow, 2)}</b>Received</div>
                <div className="stat"><b>{fmtNumber(q.data.summary.outflow, 2)}</b>Sent</div>
                <div className="stat"><b>{q.data.summary.unique_senders}</b>Senders</div>
                <div className="stat"><b>{q.data.summary.tx_count}</b>Transfers read</div>
                <div className="stat"><b className="small">{fmtDateTime(q.data.summary.first_seen)}</b>First seen</div>
              </div>
            )}
            <h2>Where the money went ({q.data.network})</h2>
            {q.data.edges.length === 0 ? <p className="muted">No outgoing transfers found.</p> : (
              <div className="tablewrap">
                <table>
                  <thead><tr><th>Hop</th><th>From</th><th>To</th><th>Amount</th><th>Listed</th></tr></thead>
                  <tbody>
                    {q.data.edges.map((e, i) => {
                      const flag = q.data.nodes.find((n) => n.id === e.to)?.flag;
                      return (
                        <tr key={i}>
                          <td>{e.hop}</td>
                          <td className="mono" title={e.from}>{shorten(e.from)}</td>
                          <td className="mono" title={e.to}>{shorten(e.to)}</td>
                          <td>{fmtNumber(e.amount, 2)}</td>
                          <td>{flag ? <span className="band high">{flag.label} ({flag.source})</span> : <span className="muted">—</span>}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
