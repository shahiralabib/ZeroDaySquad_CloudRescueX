import { useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, Bot, CheckCircle2, Clock3, RefreshCw, Server, ShieldAlert, Sparkles } from "lucide-react";
import { EmptyState, ErrorState, formatDate, LoadingState, localDayKey, Panel, parseTimestamp, StatusPill } from "../components/States";
import { fetchAIStatus, fetchHealth, fetchNotifications, fetchOverview, fetchStats } from "../lib/api";
import type { DashboardStats, Incident, Notification, Overview as OverviewData, ProviderStatus } from "../types";

type OverviewDataState = {
  overview: OverviewData;
  stats: DashboardStats;
  ai: ProviderStatus;
  api: string;
  notifications: Notification[];
};

function MetricCard({ label, value, detail, icon: Icon, tone }: { label: string; value: string | number; detail: string; icon: typeof Activity; tone: string }) {
  return <div className="soc-metric-card"><div className="flex items-start justify-between"><div><p className="soc-kicker">{label}</p><p className="mt-3 text-2xl font-semibold tracking-tight text-white">{value}</p></div><div className={`soc-metric-icon ${tone}`}><Icon size={17} /></div></div><p className="mt-3 text-xs text-slate-500">{detail}</p></div>;
}

function TrendChart({ incidents }: { incidents: Incident[] }) {
  const trend = useMemo(() => {
    const days = Array.from({ length: 7 }, (_, index) => {
      const date = new Date();
      date.setHours(0, 0, 0, 0);
      date.setDate(date.getDate() - (6 - index));
      return date;
    });
    // Bucket by the viewer's local calendar day. Timestamps are parsed as UTC instants first, so an
    // incident detected late in the UTC day is counted on the correct local day.
    const detectedDays = incidents.map((incident) => {
      const detected = parseTimestamp(incident.detection_timestamp);
      return detected ? localDayKey(detected) : null;
    });
    return days.map((date) => {
      const day = localDayKey(date);
      return { label: date.toLocaleDateString(undefined, { weekday: "short" }), count: detectedDays.filter((detectedDay) => detectedDay === day).length };
    });
  }, [incidents]);
  const max = Math.max(1, ...trend.map((item) => item.count));
  if (!incidents.length) return <EmptyState message="Incident trend unavailable until incident records are available." />;
  return <div className="p-5"><div className="flex h-44 items-end gap-2 sm:gap-4">{trend.map((item) => <div key={item.label} className="flex h-full flex-1 flex-col items-center justify-end gap-2"><div className="w-full max-w-12 rounded-t bg-cyan/80 transition-all" style={{ height: `${Math.max(8, (item.count / max) * 125)}px` }} title={`${item.count} incidents`} /><span className="text-[10px] uppercase tracking-wide text-slate-600">{item.label}</span></div>)}</div><p className="mt-3 text-xs text-slate-500">Based on the seven-day window of loaded incident records.</p></div>;
}

export function Overview() {
  const [data, setData] = useState<OverviewDataState | null>(null);
  const [error, setError] = useState("");
  const load = () => {
    setError("");
    return Promise.all([fetchOverview(), fetchStats(), fetchAIStatus(), fetchHealth(), fetchNotifications()])
      .then(([overview, stats, ai, health, notifications]) => setData({ overview, stats, ai, api: health.status, notifications }))
      .catch((reason: Error) => setError(reason.message));
  };
  useEffect(() => { void load(); const timer = window.setInterval(() => void load(), 15000); return () => window.clearInterval(timer); }, []);
  if (error) return <ErrorState message={error} />;
  if (!data) return <LoadingState />;

  const { overview, stats, ai, notifications } = data;
  const recentIncidents = overview.incidents.slice(0, 5);
  const latestTriage = overview.incidents.find((incident) => incident.recovery_recommendation || incident.probable_root_cause);
  const maxSeverity = Math.max(1, ...Object.values(stats.severity_distribution));

  return <div className="space-y-7">
    <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div><p className="soc-eyebrow">OPERATIONS CENTER</p><h1 className="mt-1 text-2xl font-semibold tracking-tight text-white sm:text-3xl">Resilience at a glance</h1><p className="mt-2 text-sm text-slate-400">Live service health, incident signals, and verified recovery outcomes.</p></div>
      <button onClick={() => void load()} className="soc-secondary-button"><RefreshCw size={15} />Refresh data</button>
    </div>
    {overview.seeded_demo_data && <div className="soc-demo-banner"><Sparkles size={16} /><span><strong>Demonstration environment.</strong> Seeded records are simulated and clearly labelled below.</span></div>}
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
      <MetricCard label="Services online" value={stats.healthy_services} detail={`${stats.total_services} total services`} icon={CheckCircle2} tone="soc-tone-green" />
      <MetricCard label="Unhealthy services" value={stats.unhealthy_services} detail="Needs operator attention" icon={AlertTriangle} tone="soc-tone-red" />
      <MetricCard label="Active incidents" value={stats.active_incidents} detail="Currently in response" icon={ShieldAlert} tone="soc-tone-orange" />
      <MetricCard label="Escalated" value={stats.escalated_incidents} detail="Awaiting intervention" icon={Activity} tone="soc-tone-violet" />
      <MetricCard label="Resolved incidents" value={stats.resolved_incidents} detail="Recovery completed" icon={CheckCircle2} tone="soc-tone-cyan" />
      <MetricCard label="Avg verified recovery" value={stats.average_verified_recovery_seconds == null ? "—" : `${Math.round(stats.average_verified_recovery_seconds)}s`} detail="Verified outcomes only" icon={Clock3} tone="soc-tone-slate" />
    </div>
    <div className="grid gap-5 xl:grid-cols-3">
      <Panel title="Incident trend" className="xl:col-span-2"><TrendChart incidents={overview.incidents} /></Panel>
      <Panel title="Service health"><div className="divide-y divide-slate-800">{overview.services.length ? overview.services.slice(0, 5).map((service) => <div key={service.id} className="flex items-center justify-between px-5 py-4"><div className="flex min-w-0 items-center gap-3"><span className={`h-2 w-2 shrink-0 rounded-full ${service.status === "healthy" ? "bg-emerald-400" : "bg-red-400"}`} /><div className="min-w-0"><p className="truncate text-sm font-medium text-slate-200">{service.name}</p><p className="text-xs text-slate-500">{service.environment}</p></div></div><StatusPill value={service.status} /></div>) : <EmptyState message="Service health unavailable." />}</div></Panel>
    </div>
    <div className="grid gap-5 lg:grid-cols-3">
      <Panel title="Severity distribution"><div className="space-y-4 p-5">{Object.entries(stats.severity_distribution).length ? Object.entries(stats.severity_distribution).map(([severity, count]) => <div key={severity}><div className="mb-1 flex justify-between text-xs"><span className="capitalize text-slate-400">{severity}</span><span className="text-slate-300">{count}</span></div><div className="h-2 rounded-full bg-slate-800"><div className="h-2 rounded-full bg-cyan" style={{ width: `${(count / maxSeverity) * 100}%` }} /></div></div>) : <EmptyState message="Severity data unavailable." />}</div></Panel>
      <Panel title="AI-assisted triage" className="lg:col-span-2"><div className="p-5">{latestTriage ? <div className="flex gap-4"><div className="soc-ai-icon"><Bot size={19} /></div><div><div className="flex flex-wrap items-center gap-2"><p className="font-medium text-slate-200">Latest evidence-backed recommendation</p><StatusPill value={ai.simulated ? "simulated provider" : ai.provider} /></div><p className="mt-3 text-sm leading-6 text-slate-400">{latestTriage.recovery_recommendation ?? latestTriage.probable_root_cause}</p><p className="mt-3 text-xs text-slate-600">Derived from incident data; AI does not authorize recovery actions.</p></div></div> : <EmptyState message="AI triage summary unavailable until an investigation produces a recommendation." />}</div></Panel>
    </div>
    <div className="grid gap-5 xl:grid-cols-3">
      <Panel title="Recent incidents" className="xl:col-span-2"><div className="overflow-x-auto"><table className="w-full min-w-[560px] text-left"><thead><tr className="border-b border-slate-800 text-[10px] uppercase tracking-wider text-slate-600"><th className="px-5 py-3 font-medium">Incident</th><th className="px-3 py-3 font-medium">Severity</th><th className="px-3 py-3 font-medium">State</th><th className="px-5 py-3 text-right font-medium">Detected</th></tr></thead><tbody className="divide-y divide-slate-800">{recentIncidents.length ? recentIncidents.map((incident) => <tr key={incident.id} className="text-sm"><td className="px-5 py-4"><p className="max-w-[280px] truncate font-medium text-slate-200">{incident.summary}</p><p className="mt-1 text-xs text-slate-500">{incident.service_name}{incident.is_demo ? " · SIMULATED" : ""}</p></td><td className="px-3 py-4"><StatusPill value={incident.severity} /></td><td className="px-3 py-4"><StatusPill value={incident.state} /></td><td className="px-5 py-4 text-right text-xs text-slate-500">{formatDate(incident.detection_timestamp)}</td></tr>) : <tr><td colSpan={4}><EmptyState message="No incident records available." /></td></tr>}</tbody></table></div></Panel>
      <Panel title="Recent activity"><div className="divide-y divide-slate-800">{notifications.length ? notifications.slice(0, 5).map((notification) => <div key={notification.id} className="px-5 py-4"><div className="flex items-start gap-3"><div className="mt-0.5 text-cyan"><Server size={15} /></div><div className="min-w-0"><p className="text-sm text-slate-300">{notification.reason}</p><p className="mt-1 text-xs text-slate-500">{notification.service_name} · {formatDate(notification.created_at)}</p></div></div></div>) : <EmptyState message="Recent activity unavailable." />}</div></Panel>
    </div>
    <div className="flex items-center gap-2 text-xs text-slate-600"><span className={`h-1.5 w-1.5 rounded-full ${data.api === "ok" ? "bg-emerald-400" : "bg-amber-400"}`} />API status: {data.api} · {ai.message}</div>
  </div>;
}
