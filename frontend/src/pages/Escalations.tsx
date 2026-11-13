import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { AlertOctagon } from "lucide-react";
import { EmptyState, ErrorBanner, ErrorState, escalationStatus, formatDate, LoadingState, PageHeader, Panel, StatusPill, SuccessBanner, type ActionNotice } from "../components/States";
import { acknowledgeEscalation, fetchEscalations, rejectRecovery, retryRecovery } from "../lib/api";
import type { Escalation } from "../types";

const REJECTION_REASON = "Administrator rejected the proposed recovery action.";
const HISTORY_LIMIT = 50;

// Acknowledge and reject return the updated escalation; retry returns a recovery execution.
const isEscalation = (value: unknown): value is Escalation => typeof value === "object" && value !== null && "rejection_reason" in value && "incident_id" in value;

export function Escalations() {
  const [items, setItems] = useState<Escalation[] | null>(null); const [loadError, setLoadError] = useState(""); const [notice, setNotice] = useState<ActionNotice | null>(null); const [success, setSuccess] = useState<string | null>(null); const loaded = useRef(false); const [busy, setBusy] = useState<number | null>(null); const inFlight = useRef(false);
  const load = () => fetchEscalations().then((records) => { setItems(records); loaded.current = true; setLoadError(""); }).catch((reason: Error) => { if (loaded.current) setNotice((current) => current ?? { title: "Could not refresh data", message: reason.message, retry: () => { setNotice(null); void load(); } }); else setLoadError(reason.message); }); useEffect(() => { void load(); }, []);
  // One action at a time: the ref blocks a second click before React has re-rendered the disabled buttons.
  // A failed action keeps the page and its data; the list is refreshed afterwards because a rejected action can still change server state.
  const action = async (item: Escalation, successMessage: string, fn: () => Promise<unknown>) => {
    if (inFlight.current) return;
    inFlight.current = true; setBusy(item.id); setNotice(null); setSuccess(null);
    try {
      const result = await fn();
      // Show the persisted outcome immediately, then re-read the list from the server.
      if (isEscalation(result)) setItems((current) => current && current.map((entry) => (entry.id === result.id ? result : entry)));
      setSuccess(successMessage);
      await load();
    } catch (reason) { setNotice({ message: (reason as Error).message, retry: () => void action(item, successMessage, fn) }); await load(); } finally { inFlight.current = false; setBusy(null); }
  };
  if (!items) return loadError ? <ErrorState message={loadError} onRetry={() => { setLoadError(""); void load(); }} /> : <LoadingState />;
  const pending = items.filter((item) => escalationStatus(item) === "pending");
  const processed = items.filter((item) => escalationStatus(item) !== "pending");
  const working = busy !== null;
  return <div className="space-y-6"><PageHeader eyebrow="HUMAN OVERSIGHT" title="Administrator escalations" description={`Review unresolved incidents and authorize the next safe step. ${pending.length} pending · ${processed.length} processed.`} />{success && <SuccessBanner message={success} onDismiss={() => setSuccess(null)} />}{notice && <ErrorBanner notice={notice} onDismiss={() => setNotice(null)} />}<div className="space-y-4">{pending.length ? pending.map((item) => <Panel key={item.id}><div className="flex flex-col gap-5 p-5"><div className="flex items-start justify-between gap-4"><div className="flex gap-3"><AlertOctagon className="mt-1 text-red-300" size={19} /><div><div className="flex flex-wrap items-center gap-2"><Link to={`/incidents/${item.incident_id}`} className="font-medium text-cyan hover:underline">Incident #{item.incident_id}</Link><StatusPill value={item.severity} /><StatusPill value="pending" /></div><p className="mt-2 text-sm text-slate-300">{item.reason}</p><p className="mt-1 text-xs text-slate-500">{formatDate(item.escalated_at)} · {item.assigned_administrator ?? "Unassigned"}</p></div></div></div><div className="grid gap-3 rounded-lg bg-slate-950 p-4 text-xs md:grid-cols-2"><div><p className="uppercase tracking-wide text-slate-600">AI findings</p><pre className="mt-2 whitespace-pre-wrap text-slate-400">{JSON.stringify(item.ai_findings, null, 2)}</pre></div><div><p className="uppercase tracking-wide text-slate-600">Next steps</p><p className="mt-2 text-slate-400">{item.recommended_next_steps}</p></div></div><div className="flex flex-wrap gap-2"><button disabled={working} onClick={() => action(item, `Escalation #${item.id} for incident #${item.incident_id} acknowledged. The incident stays open.`, () => acknowledgeEscalation(item.incident_id, item.id))} className="rounded-lg bg-cyan px-3 py-2 text-xs font-medium text-slate-950 disabled:opacity-40">{busy === item.id ? "Working…" : "Acknowledge"}</button><button disabled={working} onClick={() => action(item, `Safe recovery retried for incident #${item.incident_id}.`, () => retryRecovery(item.incident_id, "restart_demo_application"))} className="rounded-lg border border-emerald-800 px-3 py-2 text-xs text-emerald-300 disabled:opacity-40">Retry safe recovery</button><button disabled={working} onClick={() => action(item, `Recovery rejected for incident #${item.incident_id} (escalation #${item.id}). The incident stays open for manual handling.`, () => rejectRecovery(item.incident_id, REJECTION_REASON, item.id))} className="rounded-lg border border-red-800 px-3 py-2 text-xs text-red-300 disabled:opacity-40">Reject proposed action</button></div></div></Panel>) : <EmptyState message="No escalated incidents require administrator attention." />}</div>{processed.length > 0 && <Panel title="Processed escalations (history)"><div className="divide-y divide-slate-800">{processed.slice(0, HISTORY_LIMIT).map((item) => { const status = escalationStatus(item); return <div key={item.id} className="flex flex-col gap-1 px-5 py-4 text-sm"><div className="flex flex-wrap items-center gap-2"><Link to={`/incidents/${item.incident_id}`} className="font-medium text-cyan hover:underline">Incident #{item.incident_id}</Link><StatusPill value={item.severity} /><StatusPill value={status} /></div><p className="text-slate-300">{item.reason}</p>{status === "rejected" && item.rejection_reason && <p className="text-xs text-slate-400">Rejection reason: {item.rejection_reason}</p>}<p className="text-xs text-slate-500">Escalated {formatDate(item.escalated_at)} · {status === "rejected" ? "Recovery rejected" : "Acknowledged"} {formatDate(item.acknowledged_at)} by {item.assigned_administrator ?? "an administrator"}</p></div>; })}</div>{processed.length > HISTORY_LIMIT && <p className="border-t border-slate-800 px-5 py-3 text-xs text-slate-500">Showing the {HISTORY_LIMIT} most recent of {processed.length} processed escalations. All records remain available from the API.</p>}</Panel>}</div>;
}
