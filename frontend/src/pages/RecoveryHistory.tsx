import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { EmptyState, ErrorState, formatDate, LoadingState, PageHeader, Panel, StatusPill } from "../components/States";
import { fetchAllRecovery, fetchIncidents } from "../lib/api";
import type { Incident, RecoveryExecution } from "../types";

export function RecoveryHistory() {
  const [records, setRecords] = useState<RecoveryExecution[] | null>(null); const [incidents, setIncidents] = useState<Incident[]>([]); const [error, setError] = useState("");
  useEffect(() => { Promise.all([fetchAllRecovery(), fetchIncidents()]).then(([actions, incidentRecords]) => { setRecords(actions); setIncidents(incidentRecords); }).catch((reason: Error) => setError(reason.message)); }, []);
  if (error) return <ErrorState message={error} />; if (!records) return <LoadingState />;
  const names = new Map(incidents.map((incident) => [incident.id, incident]));
  return <div className="space-y-6"><PageHeader eyebrow="RECOVERY OPERATIONS" title="Recovery history" description="Every execution is shown separately from its independent verification result." /><Panel>{records.length ? <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-5 py-3">Action</th><th className="px-5 py-3">Target</th><th className="px-5 py-3">Started</th><th className="px-5 py-3">Outcome</th><th className="px-5 py-3">Incident</th></tr></thead><tbody className="divide-y divide-slate-800">{records.map((record) => <tr key={record.id}><td className="px-5 py-4 font-medium">{record.action_id}</td><td className="px-5 py-4 text-slate-400">{names.get(record.incident_id)?.service_name ?? `Service #${record.service_id}`}</td><td className="px-5 py-4 text-xs text-slate-400">{formatDate(record.started_at)}{record.completed_at && <span className="block text-slate-600">Completed {formatDate(record.completed_at)}</span>}</td><td className="px-5 py-4"><StatusPill value={record.status} /></td><td className="px-5 py-4"><Link className="text-cyan hover:underline" to={`/incidents/${record.incident_id}`}>#{record.incident_id}</Link></td></tr>)}</tbody></table></div> : <EmptyState message="No recovery executions recorded." />}</Panel></div>;
}
