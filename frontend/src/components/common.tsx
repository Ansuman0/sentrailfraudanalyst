import type { ReactNode } from "react";
import { ApiError } from "../services/http";
import type { Band } from "../types/api";
import { humanize } from "../utils/format";

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="loading" role="status">
      <span className="spin" aria-hidden="true" /> {label}
    </div>
  );
}

/** Shows the API's own message (FastAPI "detail"), which is written for end users. */
export function ErrorBox({ error, title }: { error: unknown; title?: string }) {
  const msg = error instanceof ApiError || error instanceof Error ? error.message : "Something went wrong";
  return (
    <div className="alertbox" role="alert">
      {title && <b>{title}. </b>}
      {msg}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="muted empty">{children}</p>;
}

export function BandBadge({ band }: { band: Band }) {
  return <span className={`band ${band}`}>{band}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  return <span className={`status s-${status}`}>{humanize(status)}</span>;
}

const BAND_COLOR: Record<Band, string> = { high: "var(--high)", medium: "var(--med)", low: "var(--low)" };

export function Score({ score, band }: { score: number; band: Band }) {
  return (
    <span className="score" aria-label={`Risk score ${score} of 100`}>
      {score}
      <i aria-hidden="true">
        <b style={{ width: `${Math.min(100, Math.max(0, score))}%`, background: BAND_COLOR[band] }} />
      </i>
    </span>
  );
}

export function PageHeader({ title, sub, children }: { title: string; sub?: string; children?: ReactNode }) {
  return (
    <div className="pagehead">
      <div>
        <h1>{title}</h1>
        {sub && <p className="sub">{sub}</p>}
      </div>
      {children}
    </div>
  );
}
