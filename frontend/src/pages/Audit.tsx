import { useMutation, useQuery } from "@tanstack/react-query";
import { useAuth } from "../hooks/useAuth";
import { Empty, ErrorBox, Loading, PageHeader } from "../components/common";
import { govern, governance } from "../services/sentrail";
import { fmtDateTime, humanize, shorten } from "../utils/format";

export function Audit() {
  const events = useQuery({ queryKey: ["audit"], queryFn: () => govern.audit(200) });
  const verify = useQuery({ queryKey: ["audit-verify"], queryFn: govern.verifyAudit, enabled: false });
  const { can } = useAuth();
  // A signed file through a one-time link: asked for and fetched in one go, then handed to the browser as a download.
  const exportLog = useMutation({
    mutationFn: async (format: "json" | "csv") => {
      const link = await governance.exportAudit(format);
      const text = await governance.download(link.download_path);
      const url = URL.createObjectURL(new Blob([text], { type: format === "json" ? "application/json" : "text/csv" }));
      const a = document.createElement("a");
      a.href = url; a.download = link.filename; a.click();
      URL.revokeObjectURL(url);
      return link.filename;
    },
  });

  return (
    <>
      <PageHeader title="Audit log" sub="Every view, search, AI run and decision, with who did it and why. Each event is hash-chained to the one before.">
        <button className="btn" onClick={() => void verify.refetch()} disabled={verify.isFetching}>
          {verify.isFetching ? "Checking…" : "Verify chain"}
        </button>
        {can("audit.export") && (
          <>
            <button className="btn" disabled={exportLog.isPending} onClick={() => exportLog.mutate("json")}>Export signed JSON</button>
            <button className="btn" disabled={exportLog.isPending} onClick={() => exportLog.mutate("csv")}>Export CSV</button>
          </>
        )}
      </PageHeader>
      {verify.data && (
        <div className={`alertbox ${verify.data.ok ? "clear" : ""}`} role="status">
          {verify.data.ok
            ? `Chain intact: ${verify.data.events} events, none changed, removed or reordered.`
            : `Chain broken at event ${verify.data.broken_at}: ${verify.data.reason}.`}
        </div>
      )}
      {verify.isError && <ErrorBox error={verify.error} />}
      {exportLog.isError && <ErrorBox error={exportLog.error} title="The export didn't complete" />}
      {exportLog.isSuccess && <p className="verified" role="status">Downloaded {exportLog.data}. It is watermarked with your name and signed; the export is recorded in the audit log.</p>}
      {events.isPending ? <Loading /> : events.isError ? <ErrorBox error={events.error} /> : events.data.length === 0 ? (
        <Empty>No events yet.</Empty>
      ) : (
        <div className="tablewrap">
          <table>
            <thead><tr><th>#</th><th>When</th><th>Action</th><th>Target</th><th>Role</th><th>Actor</th><th>IP</th></tr></thead>
            <tbody>
              {events.data.map((e) => (
                <tr key={e.seq}>
                  <td className="muted">{e.seq}</td>
                  <td className="muted">{fmtDateTime(e.at)}</td>
                  <td>{humanize(e.action)}</td>
                  <td className="mono">{e.target ?? "—"}</td>
                  <td>{e.role ?? "—"}</td>
                  <td className="mono" title={e.actor ?? ""}>{e.actor ? shorten(e.actor, 4) : "system"}</td>
                  <td className="mono">{e.ip ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
