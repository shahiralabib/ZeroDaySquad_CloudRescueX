import { useEffect, useRef, useState } from "react";
import { RefreshCw, Search } from "lucide-react";
import { useAuth } from "../components/AuthContext";
import { permissionHint } from "../lib/auth";
import { EmptyState, ErrorBanner, ErrorState, formatDate, LoadingState, PageHeader, Panel, StatusPill, type ActionNotice } from "../components/States";
import { fetchServiceHealth, fetchServices, runHealthCheck } from "../lib/api";
import type { HealthCheck, Service } from "../types";

// One consistent indicator for demo services. The environment value "demo" is shown as the DEMO badge instead of
// repeating the same word twice; other environments keep their name, with the badge added for simulated services.
// Only the display changes: service.environment and service.simulation_status are untouched (search still uses them).
function EnvironmentCell({ service }: { service: Service }) {
  const isDemoEnvironment = service.environment.toLowerCase() === "demo";
  return <>{!isDemoEnvironment && service.environment}{(isDemoEnvironment || service.simulation_status) && <span className={`${isDemoEnvironment ? "" : "ml-2 "}text-[10px] text-amber-300`}>DEMO</span>}</>;
}

export function Services() {
  const { can } = useAuth();
  const [services, setServices] = useState<Service[] | null>(null);
  const [selected, setSelected] = useState<Service | null>(null);
  const [checks, setChecks] = useState<HealthCheck[]>([]);
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState<number | null>(null);
  const [loadError, setLoadError] = useState("");
  const [notice, setNotice] = useState<ActionNotice | null>(null);
  const loaded = useRef(false);
  const load = (): Promise<void> => fetchServices().then((records) => { setServices(records); loaded.current = true; setLoadError(""); }).catch((reason: Error) => { if (loaded.current) setNotice((current) => current ?? { title: "Could not refresh services", message: reason.message, retry: () => { setNotice(null); void load(); } }); else setLoadError(reason.message); });
  useEffect(() => { void load(); }, []);
  const inspect = (service: Service) => { setSelected(service); setNotice(null); fetchServiceHealth(service.id).then(setChecks).catch((reason: Error) => setNotice({ title: `Could not load health observations for ${service.name}`, message: reason.message, retry: () => inspect(service) })); };
  // A failed health check keeps the page and the service list.
  const check = async (service: Service) => { setBusy(service.id); setNotice(null); try { await runHealthCheck(service.id); await load(); if (selected?.id === service.id) inspect(service); } catch (reason) { setNotice({ title: `Health check failed for ${service.name}`, message: (reason as Error).message, retry: () => void check(service) }); } finally { setBusy(null); } };
  if (!services) return loadError ? <ErrorState message={loadError} onRetry={() => { setLoadError(""); void load(); }} /> : <LoadingState />;
  const filtered = services.filter((service) => service.name.toLowerCase().includes(query.toLowerCase()) || service.environment.toLowerCase().includes(query.toLowerCase()));
  return <div className="space-y-6"><PageHeader eyebrow="INVENTORY" title="Services" description="Inspect live health observations and monitoring configuration." action={<button onClick={() => { setNotice(null); void load(); }} className="rounded-lg border border-slate-700 p-2 text-slate-300 hover:text-cyan" aria-label="Refresh services"><RefreshCw size={17} /></button>} />{notice && <ErrorBanner notice={notice} onDismiss={() => setNotice(null)} />}<div className="relative max-w-md"><Search className="absolute left-3 top-2.5 text-slate-500" size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search services" className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-9 pr-3 text-sm outline-none focus:border-cyan" /></div><Panel>{filtered.length ? <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-5 py-3">Service</th><th className="px-5 py-3">Environment</th><th className="px-5 py-3">Health</th><th className="px-5 py-3">Last check</th><th className="px-5 py-3">Failures</th><th className="px-5 py-3" /></tr></thead><tbody className="divide-y divide-slate-800">{filtered.map((service) => <tr key={service.id}><td className="px-5 py-4"><p className="font-medium">{service.name}</p><p className="text-xs text-slate-500">{service.description || "No description"}</p></td><td className="px-5 py-4 text-slate-400"><EnvironmentCell service={service} /></td><td className="px-5 py-4"><StatusPill value={service.status} /></td><td className="px-5 py-4 text-xs text-slate-400">{formatDate(service.last_successful_check ?? service.last_failed_check)}</td><td className="px-5 py-4">{service.consecutive_failure_count}</td><td className="px-5 py-4 text-right"><button onClick={() => check(service)} disabled={busy === service.id || !can("runHealthCheck")} title={can("runHealthCheck") ? undefined : permissionHint("runHealthCheck")} className="mr-3 text-xs text-cyan disabled:opacity-40">{busy === service.id ? "Checking…" : "Check now"}</button><button onClick={() => inspect(service)} className="text-xs text-slate-300 hover:text-cyan">Inspect</button></td></tr>)}</tbody></table></div> : <EmptyState message="No matching services." />}</Panel>{selected && <Panel title={`${selected.name} details`}><div className="grid gap-4 p-5 sm:grid-cols-3"><div><p className="text-xs text-slate-500">Monitoring interval</p><p className="mt-1">{selected.monitoring_interval_seconds}s</p></div><div><p className="text-xs text-slate-500">Timeout</p><p className="mt-1">{selected.health_check_timeout_seconds}s</p></div><div><p className="text-xs text-slate-500">Failure threshold</p><p className="mt-1">{selected.consecutive_failure_count} / configured threshold</p></div></div><div className="border-t border-slate-800 p-5"><h3 className="text-sm font-medium">Recent health observations</h3>{checks.length ? <div className="mt-3 space-y-2">{checks.slice(0, 8).map((checkItem) => <div key={checkItem.id} className="flex items-center justify-between text-xs"><span>{formatDate(checkItem.observed_at)}</span><span>{checkItem.response_time_ms}ms</span><StatusPill value={checkItem.status} /></div>)}</div> : <p className="mt-3 text-sm text-slate-500">No health checks recorded.</p>}</div></Panel>}</div>;
}
