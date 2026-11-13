import { useEffect, useRef } from "react";

export function LoadingState() {
  return <div className="rounded-xl border border-slate-800 bg-panel p-10 text-center text-sm text-slate-400">Loading live operational data…</div>;
}

/** Full-page error. Use it only when a page's initial data cannot be loaded. */
export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return <div role="alert" className="rounded-xl border border-red-900/60 bg-red-950/20 p-5 text-sm text-red-300"><p className="font-medium">Unable to load operational data</p><p className="mt-1 text-red-400/80">{message}</p>{onRetry && <button onClick={onRetry} className="mt-3 rounded-lg border border-red-800 px-3 py-1.5 text-xs text-red-200 hover:bg-red-950/40">Retry</button>}</div>;
}

/** A failed user action or background refresh, shown while the page and its data stay visible. */
export type ActionNotice = { message: string; title?: string; retry?: () => void };

export function ErrorBanner({ notice, onDismiss }: { notice: ActionNotice; onDismiss: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { ref.current?.scrollIntoView?.({ block: "nearest", behavior: "smooth" }); }, [notice]);
  return <div ref={ref} role="alert" className="flex items-start justify-between gap-4 rounded-xl border border-red-900/60 bg-red-950/20 p-4 text-sm text-red-300"><div className="min-w-0"><p className="font-medium">{notice.title ?? "Action failed"}</p><p className="mt-1 break-words text-red-400/80">{notice.message}</p></div><div className="flex shrink-0 gap-2">{notice.retry && <button onClick={notice.retry} className="rounded-lg border border-red-800 px-3 py-1.5 text-xs text-red-200 hover:bg-red-950/40">Retry</button>}<button onClick={onDismiss} aria-label="Dismiss error" className="rounded-lg px-3 py-1.5 text-xs text-red-300 hover:bg-red-950/40">Dismiss</button></div></div>;
}

/** Confirmation of a completed user action. Dismissible; the page and its data stay visible. */
export function SuccessBanner({ message, onDismiss }: { message: string; onDismiss: () => void }) {
  return <div role="status" className="flex items-start justify-between gap-4 rounded-xl border border-emerald-900/60 bg-emerald-950/20 p-4 text-sm text-emerald-300"><p className="min-w-0 break-words">{message}</p><button onClick={onDismiss} aria-label="Dismiss message" className="shrink-0 rounded-lg px-3 py-1.5 text-xs text-emerald-300 hover:bg-emerald-950/40">Dismiss</button></div>;
}

/** An escalation is pending until an administrator acknowledges it or rejects its recovery (the API persists this as `status`). */
export function escalationStatus(item: { status?: string; acknowledged: boolean }): "pending" | "acknowledged" | "rejected" {
  if (item.status === "rejected" || item.status === "acknowledged" || item.status === "pending") return item.status;
  return item.acknowledged ? "acknowledged" : "pending";
}

export function EmptyState({ message }: { message: string }) {
  return <div className="rounded-xl border border-dashed border-slate-700 p-10 text-center text-sm text-slate-500">{message}</div>;
}

export function PageHeader({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: React.ReactNode }) {
  return <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between"><div>{eyebrow && <p className="text-sm font-medium text-cyan">{eyebrow}</p>}<h1 className="mt-1 text-2xl font-semibold tracking-tight">{title}</h1>{description && <p className="mt-2 text-sm text-slate-400">{description}</p>}</div>{action}</div>;
}

export function Panel({ title, children, className = "" }: { title?: string; children: React.ReactNode; className?: string }) {
  return <section className={`rounded-xl border border-slate-800 bg-panel ${className}`}>{title && <div className="border-b border-slate-800 px-5 py-4"><h2 className="font-medium">{title}</h2></div>}{children}</section>;
}

// Statuses are classified by whole words, never by substring: "unhealthy" contains "healthy",
// so substring matching made it green. Danger wins over success if both kinds of word appear.
const DANGER_WORDS = new Set(["unhealthy", "failed", "failure", "escalated", "escalation", "escalate", "rejected"]);
const SUCCESS_WORDS = new Set(["healthy", "resolved", "success", "successful", "completed"]);

export function statusTone(value: string): "success" | "danger" | "warning" {
  const words = value.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  if (words.some((word) => DANGER_WORDS.has(word))) return "danger";
  if (words.some((word) => SUCCESS_WORDS.has(word))) return "success";
  return "warning";
}

const TONE_CLASSES = {
  success: "bg-emerald-950/50 text-emerald-300",
  danger: "bg-red-950/50 text-red-300",
  warning: "bg-amber-950/50 text-amber-300",
} as const;

export function StatusPill({ value }: { value: string }) {
  return <span className={`rounded-full px-2.5 py-1 text-[11px] font-medium uppercase tracking-wide ${TONE_CLASSES[statusTone(value)]}`}>{value.replace(/_/g, " ")}</span>;
}

// The API returns datetimes in UTC. SQLAlchemy/SQLite hands back values without a UTC marker
// ("2026-11-12T23:57:32"), but values set during the same request carry one ("…Z"). `new Date()`
// reads a marker-less string as local time, which shifts every such time by the viewer's UTC offset.
// Values with an explicit "Z" or offset keep their meaning; marker-less values are taken as UTC.
const TIMESTAMP_PATTERN = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)\s*(Z|[+-]\d{2}(?::?\d{2})?)?$/i;

export function parseTimestamp(value: string | null | undefined): Date | null {
  if (!value) return null;
  const text = value.trim();
  const match = TIMESTAMP_PATTERN.exec(text);
  let parsed: Date;
  if (match) {
    const [, day, time, zone] = match;
    let offset = "Z";
    if (zone && zone.toUpperCase() !== "Z") {
      const digits = zone.slice(1).replace(":", "");
      offset = `${zone[0]}${digits.slice(0, 2)}:${digits.slice(2) || "00"}`;
    }
    parsed = new Date(`${day}T${time}${offset}`);
  } else {
    parsed = new Date(text);
  }
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

/** Calendar day (YYYY-MM-DD) of an instant in the viewer's local timezone. */
export function localDayKey(date: Date): string {
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

export function formatDate(value: string | null) {
  if (!value) return "Not recorded";
  const parsed = parseTimestamp(value);
  return parsed ? parsed.toLocaleString() : value;
}
