import type { AuthUser, DashboardStats, Escalation, HealthCheck, Incident, Investigation, IntegrationStatus, LoginResult, Notification, Overview, ProviderStatus, RecoveryAction, RecoveryExecution, Service, TimelineEvent, Verification } from "../types";
import { endSession, getToken, isCurrentToken } from "./auth";

const API_BASE = import.meta.env.VITE_API_BASE_URL || `${window.location.protocol}//${window.location.hostname}:8000`;
const JSON_HEADERS = { "Content-Type": "application/json" };

/** A failed API call. `status` is the HTTP status (0 when the API could not be reached) and `code` the API's error code.
 *  The message is safe to show: it never contains a token, a password or the request body. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string | undefined;
  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

const SESSION_REJECTED_MESSAGE = "Your session has expired or is no longer valid. Sign in again.";
const FORBIDDEN_MESSAGE = "Your role does not allow this action.";
const AUTH_NOT_CONFIGURED_MESSAGE = "Authentication is not configured on the server. Contact an administrator.";

/** `authenticated: false` is for the login call: no token is sent and a 401 is an answer to the credentials, not an ended session. */
async function request<T>(path: string, init?: RequestInit, options: { authenticated?: boolean } = {}): Promise<T> {
  const authenticated = options.authenticated !== false;
  const sentToken = authenticated ? getToken() : null;
  const headers = new Headers(init?.headers);
  if (sentToken) headers.set("Authorization", `Bearer ${sentToken}`);
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch {
    throw new ApiError("Cannot reach the API. Check your connection and the API address.", 0);
  }
  if (!response.ok) {
    let detail: unknown = `Request failed (${response.status})`;
    let code: string | undefined;
    try {
      const body = await response.json();
      detail = body.error?.message ?? body.detail?.message ?? body.detail ?? detail;
      code = typeof body.detail?.code === "string" ? body.detail.code : typeof body.error?.code === "string" ? body.error.code : undefined;
    } catch { /* non-JSON error */ }
    // 401: no valid session. 403: signed in, but the role is too low. 503: the server has no authentication set up.
    if (response.status === 401 && authenticated && code === "UNAUTHENTICATED") {
      if (sentToken !== null && isCurrentToken(sentToken)) endSession("rejected");
      throw new ApiError(SESSION_REJECTED_MESSAGE, 401, code);
    }
    if (response.status === 403 && code === "FORBIDDEN") throw new ApiError(FORBIDDEN_MESSAGE, 403, code);
    if (response.status === 503 && code === "AUTH_NOT_CONFIGURED") throw new ApiError(AUTH_NOT_CONFIGURED_MESSAGE, 503, code);
    if (response.status === 429 && code === "TOO_MANY_ATTEMPTS") {
      const seconds = Number(response.headers.get("Retry-After"));
      throw new ApiError(Number.isFinite(seconds) && seconds > 0 ? `Too many failed sign-in attempts. Try again in ${Math.ceil(seconds)} seconds.` : "Too many failed sign-in attempts. Try again later.", 429, code);
    }
    throw new ApiError(typeof detail === "string" ? detail : JSON.stringify(detail), response.status, code);
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw new ApiError(`Unexpected non-JSON response from ${path}. Check the API URL and proxy configuration.`, response.status);
  }
  return response.json() as Promise<T>;
}

export const login = (username: string, password: string) => request<LoginResult>("/api/v1/auth/login", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ username, password }) }, { authenticated: false });
export const fetchMe = () => request<AuthUser>("/api/v1/auth/me");
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
export const startSimulation = (scenario: string, seed = 42) => request<{ status: string; scenario: string; tick_count: number }>("/api/v1/simulation/start", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ scenario, seed, event_count: 10 }) });
export const stopSimulation = () => request<{ status: string; scenario: string; tick_count: number }>("/api/v1/simulation/stop", { method: "POST", headers: JSON_HEADERS });
export const resetSimulation = () => request<{ status: string; scenario: string; tick_count: number }>("/api/v1/simulation/reset", { method: "POST", headers: JSON_HEADERS });
export const runInvestigation = (id: number) => request<Investigation>(`/api/v1/incidents/${id}/investigations`, { method: "POST" });
export const runHealthCheck = (id: number) => request<HealthCheck>(`/api/v1/services/${id}/health`, { method: "POST" });
export const injectFault = (id: number, scenario: string) => request<{ scenario: string }>(`/api/v1/demo/services/${id}/fault`, { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ scenario }) });
export const resetDemo = (id: number) => request<{ scenario: string }>(`/api/v1/demo/services/${id}/reset`, { method: "POST", headers: JSON_HEADERS });
export const approveRecovery = (id: number, action_id: string, parameters: Record<string, unknown> = {}) => request<Incident>(`/api/v1/incidents/${id}/recovery/approve`, { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ action_id, parameters }) });
export const executeRecovery = (id: number, action_id: string, approved = false, parameters: Record<string, unknown> = {}) => request<RecoveryExecution>(`/api/v1/incidents/${id}/recovery`, { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ action_id, approved, parameters }) });
export const retryRecovery = (id: number, action_id: string) => request<RecoveryExecution>(`/api/v1/incidents/${id}/recovery/retry`, { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ action_id, approved: true }) });
export const tickSimulation = () => request<{ status: string; scenario: string; tick_count: number }>("/api/v1/simulation/tick", { method: "POST", headers: JSON_HEADERS });
// The escalation id targets one specific escalation; without it the API uses the incident's newest pending one.
const escalationQuery = (escalationId?: number, separator: "?" | "&" = "?") => (escalationId === undefined ? "" : `${separator}escalation_id=${escalationId}`);
export const acknowledgeEscalation = (id: number, escalationId?: number) => request<Escalation>(`/api/v1/incidents/${id}/acknowledge${escalationQuery(escalationId, "?")}`, { method: "POST", headers: JSON_HEADERS });
export const rejectRecovery = (id: number, reason: string, escalationId?: number) => request<Escalation>(`/api/v1/incidents/${id}/reject-recovery?reason=${encodeURIComponent(reason)}${escalationQuery(escalationId, "&")}`, { method: "POST", headers: JSON_HEADERS });
