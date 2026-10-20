export const fmtNumber = (n: number | null | undefined, digits = 0) =>
  n == null ? "—" : n.toLocaleString("en-CA", { maximumFractionDigits: digits });

export const fmtDateTime = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleString("en-CA", { dateStyle: "medium", timeStyle: "short" }) : "—";

/** "pending_info" -> "pending info" */
export const humanize = (s: string) => s.replace(/_/g, " ");

/** Long wallet addresses and ids, shortened for tables: "TQ7mWx…A1Ke". */
export const shorten = (s: string, keep = 6) => (s.length > keep * 2 + 3 ? `${s.slice(0, keep)}…${s.slice(-4)}` : s);

/**
 * Only same-app paths may be used as a post-sign-in destination (no open redirects):
 * "/cases/A-1" is fine; "//evil.com", "https://evil.com" and "/\\evil.com" are not.
 */
export function safeReturnPath(p: string | null | undefined): string {
  if (!p || !p.startsWith("/") || p.startsWith("//") || p.startsWith("/\\")) return "/";
  return p;
}
