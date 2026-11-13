import type { DashboardStats, Escalation, HealthCheck, Incident, Investigation, IntegrationStatus, Notification, Overview, ProviderStatus, RecoveryAction, RecoveryExecution, Service, TimelineEvent, Verification } from "../types";

const API_BASE = import.meta.env.VITE_API_BASE_URL || `${window.location.protocol}//${window.location.hostname}:8000`;
const ADMIN_TOKEN = import.meta.env.VITE_DEMO_ADMIN_TOKEN ?? "local-demo-admin";
const adminHeaders = { "X-Demo-Admin-Token": ADMIN_TOKEN, "Content-Type": "application/json" };

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      detail = body.error?.message ?? body.detail?.message ?? body.detail ?? detail;
    } catch { /* non-JSON error */ }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw new Error(`Unexpected non-JSON response from ${path}. Check the API URL and proxy configuration.`);
  }
  return response.json() as Promise<T>;
}
export const fetchOverview = () => request<Overview>("/api/v1/overview");
export const fetchHealth = () => request<{ status: string; environment: string; mode: string; simulated: boolean; data_source: string }>("/health");
export const fetchMode = () => request<{ mode: string; simulated: boolean; data_source: string; external_integrations_available: boolean }>("/api/v1/mode");
export const fetchAIStatus = () => request<ProviderStatus>("/api/v1/ai/status");
export const fetchIntegrationStatuses = () => request<IntegrationStatus[]>("/api/v1/integrations/status");
export const fetchStats = () => request<DashboardStats>("/api/v1/dashboard/stats");
export const fetchServices = () => request<Service[]>("/api/v1/services");
export const fetchService = (id: number) => request<Service>(`/api/v1/services/${id}`);
export const fetchServiceHealth = (id: number) => request<HealthCheck[]>(`/api/v1/services/${id}/health`);
export const fetchIncidents = () => request<Incident[]>("/api/v1/incidents");
export const fetchIncident = (id: number) => request<Incident>(`/api/v1/incidents/${id}`);
export const fetchTimeline = (id: number) => request<TimelineEvent[]>(`/api/v1/incidents/${id}/timeline`);
export const fetchInvestigations = (id: number) => request<Investigation[]>(`/api/v1/incidents/${id}/investigations`);
export const fetchRecovery = (id: number) => request<RecoveryExecution[]>(`/api/v1/incidents/${id}/recovery`);
export const fetchAllRecovery = () => request<RecoveryExecution[]>("/api/v1/recovery/executions");
export const fetchVerification = (id: number) => request<Verification[]>(`/api/v1/incidents/${id}/verification`);
export const fetchEscalations = () => request<Escalation[]>("/api/v1/escalations");
export const fetchIncidentEscalations = (id: number) => request<Escalation[]>(`/api/v1/incidents/${id}/escalation`);
export const fetchNotifications = () => request<Notification[]>("/api/v1/notifications");
export const fetchActions = () => request<RecoveryAction[]>("/api/v1/recovery/actions");
export const fetchScenarios = () => request<{ simulated: boolean; scenarios: string[] }>("/api/v1/demo/scenarios");
export const fetchSimulationStatus = () => request<{ scenario: string; status: string; seed: number; tick_count: number }>("/api/v1/simulation/status");
export const fetchSimulationEvents = () => request<Array<{ event_id: string; resource_key: string; category: string; event_type: string; severity: string; summary: string; observed_at: string; simulated: boolean }>>("/api/v1/simulation/events?limit=20");
export const startSimulation = (scenario: string, seed = 42) => request<{ status: string; scenario: string; tick_count: number }>("/api/v1/simulation/start", { method: "POST", headers: adminHeaders, body: JSON.stringify({ scenario, seed, event_count: 10 }) });
export const stopSimulation = () => request<{ status: string; scenario: string; tick_count: number }>("/api/v1/simulation/stop", { method: "POST", headers: adminHeaders });
export const resetSimulation = () => request<{ status: string; scenario: string; tick_count: number }>("/api/v1/simulation/reset", { method: "POST", headers: adminHeaders });
export const runInvestigation = (id: number) => request<Investigation>(`/api/v1/incidents/${id}/investigations`, { method: "POST" });
export const runHealthCheck = (id: number) => request<HealthCheck>(`/api/v1/services/${id}/health`, { method: "POST" });
export const injectFault = (id: number, scenario: string) => request<{ scenario: string }>(`/api/v1/demo/services/${id}/fault`, { method: "POST", headers: adminHeaders, body: JSON.stringify({ scenario }) });
export const resetDemo = (id: number) => request<{ scenario: string }>(`/api/v1/demo/services/${id}/reset`, { method: "POST", headers: adminHeaders });
export const approveRecovery = (id: number, action_id: string, parameters: Record<string, unknown> = {}) => request<Incident>(`/api/v1/incidents/${id}/recovery/approve`, { method: "POST", headers: adminHeaders, body: JSON.stringify({ action_id, parameters }) });
export const executeRecovery = (id: number, action_id: string, approved = false, parameters: Record<string, unknown> = {}) => request<RecoveryExecution>(`/api/v1/incidents/${id}/recovery`, { method: "POST", headers: adminHeaders, body: JSON.stringify({ action_id, approved, parameters }) });
export const retryRecovery = (id: number, action_id: string) => request<RecoveryExecution>(`/api/v1/incidents/${id}/recovery/retry`, { method: "POST", headers: adminHeaders, body: JSON.stringify({ action_id, approved: true }) });
export const tickSimulation = () => request<{ status: string; scenario: string; tick_count: number }>("/api/v1/simulation/tick", { method: "POST", headers: adminHeaders });
export const acknowledgeEscalation = (id: number) => request<Escalation>(`/api/v1/incidents/${id}/acknowledge?administrator=local-admin`, { method: "POST", headers: adminHeaders });
export const rejectRecovery = (id: number, reason: string) => request<Escalation>(`/api/v1/incidents/${id}/reject-recovery?reason=${encodeURIComponent(reason)}`, { method: "POST", headers: adminHeaders });
