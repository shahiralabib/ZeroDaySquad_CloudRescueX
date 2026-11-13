import { useEffect, useState } from "react";
import { Bell, ExternalLink } from "lucide-react";
import { ErrorState, EmptyState, LoadingState } from "../components/States";
import { fetchNotifications } from "../lib/api";
import type { Notification as NotificationRecord } from "../types";

export function Notifications() {
  const [notifications, setNotifications] = useState<NotificationRecord[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    fetchNotifications().then(setNotifications).catch((reason: Error) => setError(reason.message));
  }, []);

  if (error) return <ErrorState message={error} />;
  if (!notifications) return <LoadingState />;

  return <div className="space-y-6">
    <div><p className="text-sm font-medium text-cyan">OPERATIONS</p><h1 className="mt-2 text-2xl font-semibold">Notifications</h1><p className="mt-2 text-sm text-slate-400">Persistent escalation notifications from the backend.</p></div>
    {notifications.length === 0 ? <EmptyState message="No escalation notifications are recorded." /> : <div className="divide-y divide-slate-800 rounded-xl border border-slate-800 bg-panel">{notifications.map((notification) => <div key={notification.id} className="flex items-start justify-between gap-4 p-5"><div className="flex gap-3"><Bell size={18} className="mt-0.5 text-amber-300" /><div><div className="flex flex-wrap items-center gap-2"><p className="font-medium">{notification.service_name}</p><span className="rounded bg-red-950/50 px-2 py-0.5 text-[10px] uppercase tracking-wide text-red-300">{notification.severity}</span></div><p className="mt-1 text-sm text-slate-400">{notification.reason}</p><p className="mt-2 text-xs text-slate-600">{notification.created_at ?? "Unknown time"}</p></div></div><a className="text-slate-500 hover:text-cyan" href={notification.dashboard_link} aria-label="Open incident"><ExternalLink size={16} /></a></div>)}</div>}
  </div>;
}
