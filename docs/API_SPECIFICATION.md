# CloudRescue X API Specification

## 1. Conventions

- Base path: `/api/v1`.
- JSON over HTTPS in hosted environments.
- UUIDs for resources and ISO-8601 UTC timestamps.
- Authenticated endpoints require `Authorization: Bearer <token>`.
- Mutating requests may include `Idempotency-Key`.
- Error shape:

```json
{
  "error": {
    "code": "POLICY_DENIED",
    "message": "Recovery operation is not permitted",
    "correlation_id": "uuid",
    "details": {}
  }
}
```

## 2. Authentication and access

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/auth/login` | Public | Exchange a username and password for a signed access token |
| GET | `/auth/me` | Any signed-in user | Return the current username and role |

Implemented behavior: `POST /auth/login` takes `{"username": "...", "password": "..."}` and returns `access_token`, `token_type` (`bearer`), `expires_in` (seconds), `expires_at` (Unix time), `username` and `role`. Every failure to sign in returns the same `401 INVALID_CREDENTIALS`; too many failures return `429 TOO_MANY_ATTEMPTS` with `Retry-After`; a malformed request returns a fixed `422 INVALID_REQUEST` that never echoes what was sent. Send the token as `Authorization: Bearer <token>`. There is no refresh endpoint: tokens last `AUTH_TOKEN_TTL_MINUTES` (default 60). Users, roles and password hashes are configured on the server (see [ENVIRONMENT_VARIABLES.md](ENVIRONMENT_VARIABLES.md#authentication)). The shared `X-Demo-Admin-Token` header no longer exists and is ignored.

Error answers for protected routes: `401 UNAUTHENTICATED` (no valid token, expired token, or a user that was removed), `403 FORBIDDEN` (signed in, role too low) and `503 AUTH_NOT_CONFIGURED`. The role is always the one in the server's current configuration, never one claimed by the client. The authoritative route-by-route list is [section 9](#9-implemented-route-access-matrix); the endpoint tables in the sections above are the original design and are superseded by it where they differ.

## 3. Services and monitoring

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/services` | Viewer | List services with status and simulation metadata |
| POST | `/services` | Admin | Register a service |
| GET | `/services/{service_id}` | Viewer | Get service details |
| PATCH | `/services/{service_id}` | Admin | Update configuration |
| POST | `/services/{service_id}/checks` | Operator | Run a health check |
| GET | `/services/{service_id}/checks` | Viewer | List check results |

Create service request:

```json
{
  "name": "Checkout Demo",
  "environment": "demo",
  "monitor_type": "local_simulation",
  "check_config": {"scenario_key": "checkout_timeout"},
  "enabled": true
}
```

## 4. Incidents and evidence

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/incidents` | Viewer | Filter by state, service, severity, and time |
| POST | `/incidents` | Operator | Create an incident from diagnostic evidence |
| GET | `/incidents/{incident_id}` | Viewer | Get incident aggregate |
| POST | `/incidents/{incident_id}/investigations` | Operator | Start investigation job |
| GET | `/incidents/{incident_id}/evidence` | Viewer | List evidence |
| POST | `/incidents/{incident_id}/evidence` | Operator | Attach supplied evidence |
| GET | `/incidents/{incident_id}/timeline` | Viewer | Get ordered timeline |

Incident creation request:

```json
{
  "service_id": "uuid",
  "detection_key": "service-check:2026-11-10T01:00Z",
  "severity": "high",
  "summary": "Health check timeout",
  "evidence": [
    {
      "source_type": "health_check",
      "content": "timeout after 2 seconds",
      "observed_at": "2026-11-10T01:00:00Z"
    }
  ]
}
```

## 5. Investigation and recommendations

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/incidents/{incident_id}/investigations/{investigation_id}` | Viewer | Get investigation status/result |
| GET | `/incidents/{incident_id}/recommendations` | Viewer | List recommendations |
| POST | `/incidents/{incident_id}/recommendations/{recommendation_id}/review` | Operator | Record approve/reject decision |

Investigation result:

```json
{
  "provider": "local_deterministic",
  "simulated": true,
  "status": "completed",
  "hypotheses": [
    {
      "code": "DEPENDENCY_TIMEOUT",
      "statement": "A configured dependency exceeded its timeout",
      "confidence": 0.78,
      "evidence_ids": ["uuid"],
      "missing_evidence": []
    }
  ],
  "recommendations": [
    {
      "operation_type": "restart_demo_service",
      "parameters": {"service_id": "uuid"},
      "rationale": "Restart the simulated service and verify health",
      "risk": "low"
    }
  ]
}
```

The server validates evidence references, confidence bounds, operation types, parameters, and provider metadata. A claimed confidence score never bypasses policy or evidence requirements.

## 3a. Local simulation and telemetry

These endpoints operate entirely on the local deterministic simulation. Mutating endpoints require the admin role. Telemetry responses include a source and simulation flag and must not be presented as live infrastructure observations.

| Method | Path | Authorization | Purpose |
|---|---|---|---|
| GET | `/simulation/status` | Viewer | Return persisted scenario state |
| GET | `/mode` | Viewer | Return DEMO/LIVE mode and data-source metadata |
| GET | `/simulation/resources` | Viewer | List synthetic infrastructure resources |
| GET | `/simulation/resources/{resource_id}` | Viewer | Return one resource and its relationship metadata |
| GET | `/simulation/events` | Viewer | Paginated telemetry filtered by resource, category, severity, and UTC time |
| POST | `/simulation/start` | Admin | Start a deterministic scenario and generate a bounded event batch |
| POST | `/simulation/tick` | Admin | Generate the next event batch while a scenario is running |
| POST | `/simulation/stop` | Admin | Stop event generation |
| POST | `/simulation/reset` | Admin | Clear telemetry and restore the baseline simulation |

| GET | `/threat-intelligence/lookup?indicator=...` | Viewer | Match an indicator against the local, clearly simulated dataset |

Supported scenarios are `baseline`, `authentication_attack`, `network_disruption`, `resource_pressure`, and `configuration_drift`. Start requests accept `seed` and `event_count` so the same scenario can be reproduced during tests and demonstrations.

Phase 3 investigation endpoints:

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/ai/status` | Viewer | Report selected provider, configuration, connection, and simulation status |
| POST | `/ai/test` | Admin | Perform an authenticated provider connectivity test |
| POST | `/incidents/{incident_id}/investigations` | Operator | Investigate an incident using the configured provider |
| GET | `/incidents/{incident_id}/investigations` | Viewer | List persisted investigation attempts and results |

The local provider is returned as `local_deterministic` with `simulated: true`. Gemini is reported as connected only after `/ai/test` succeeds; configured credentials alone do not produce a connected status.

## 6. Policy, recovery, and verification

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/incidents/{incident_id}/recommendations/{recommendation_id}/validate` | Operator | Evaluate deterministic policy |
| GET | `/incidents/{incident_id}/policy-decisions` | Viewer | List policy decisions |
| POST | `/incidents/{incident_id}/actions` | Operator | Execute an approved action |
| GET | `/incidents/{incident_id}/actions` | Viewer | List action attempts |
| POST | `/incidents/{incident_id}/verifications` | Operator | Start independent verification |
| GET | `/incidents/{incident_id}/verifications/{verification_id}` | Viewer | Get verification result |

Action request:

```json
{
  "recommendation_id": "uuid",
  "approval": {"type": "human", "actor_id": "uuid"},
  "idempotency_key": "client-generated-uuid"
}
```

The endpoint rejects missing approval, stale policy decisions, non-allowlisted operations, invalid parameters, unsafe environments, and repeated execution unless the prior result is safely reusable.

Implemented Phase 4 demo recovery endpoints:

| Method | Path | Authorization | Purpose |
|---|---|---|---|
| GET | `/recovery/actions` | Viewer | List the strict simulated action catalog |
| POST | `/incidents/{incident_id}/recovery` | Operator | Policy-check and execute a recovery action (medium and high risk need the executing user's own approval) |
| POST | `/incidents/{incident_id}/recovery/approve` | Admin | Approve a medium/high-risk action |
| POST | `/incidents/{incident_id}/recovery/retry` | Operator | Retry an authorized action after escalation |
| GET | `/incidents/{incident_id}/recovery` | Viewer | List execution records |
| GET | `/incidents/{incident_id}/verification` | Viewer | List independent verification outcomes |

Recovery requests require a signed-in operator or admin. Low-risk actions may execute after deterministic policy validation; medium/high-risk actions require a one-time approval record created by an admin, valid for a limited time, bound to the incident, action and parameters, and usable only by the user who approved it (so an admin approves and then executes). The approving and executing user are recorded in the audit trail. Every successful execution is followed by two persisted health checks, and an incident is resolved only after `VERIFIED_SUCCESS`.

## 7. Escalation, audit, and administration

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/incidents/{incident_id}/escalations` | Operator | Escalate incident |
| GET | `/incidents/{incident_id}/escalations` | Viewer | View escalation attempts |
| GET | `/audit-events` | Admin | Query audit events |
| GET | `/policies` | Admin | List policy rules |
| PUT | `/policies/{policy_id}` | Admin | Update policy with audit record |
| GET | `/integrations` | Admin | View configured integrations/capabilities |
| PUT | `/integrations/{integration_id}` | Admin | Configure non-secret integration metadata |

## 8. Demo endpoints

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/demo/scenarios` | Demo user | List labelled simulated scenarios |
| POST | `/demo/scenarios/{scenario_key}/trigger` | Demo user | Trigger a safe simulated failure |
| POST | `/demo/scenarios/{scenario_key}/reset` | Demo user | Reset simulated state |

Demo endpoints must reject non-simulated adapters and must not accept arbitrary commands or infrastructure identifiers.

Phase 4 escalation and notification endpoints:

| Method | Path | Authorization | Purpose |
|---|---|---|---|
| GET | `/escalations` | Viewer | List persistent escalations |
| GET | `/incidents/{incident_id}/escalation` | Viewer | View incident escalations |
| POST | `/incidents/{incident_id}/acknowledge` | Operator | Acknowledge an escalation; it is recorded under the signed-in user (a supplied `administrator` parameter is ignored) |
| POST | `/incidents/{incident_id}/reject-recovery` | Admin | Reject the proposed recovery of an escalation |
| POST | `/incidents/{incident_id}/under-investigation` | Operator | Mark an incident as under investigation |
| GET | `/notifications` | Viewer | Read deduplicated dashboard notifications |

Phase 6 integration status:

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/integrations/status` | Operator | Report Google Monitoring, Logging, and Firestore as `connected`, `not_configured`, or `connection_failed` (it probes each integration with the server's credentials) |

Google adapter status is only `connected` after an authenticated API request succeeds. Local SQLite and deterministic AI remain the default fallback.

## 9. Implemented route access matrix

This is the authoritative list of what the running API enforces. It is pinned by `backend/tests/test_route_access.py`: every registered route must appear there with the same policy, so a route cannot be added without deciding who may call it. Roles are cumulative (viewer, then operator, then admin). Paths are under `/api/v1` unless shown otherwise.

**Public**

| Method | Path |
|---|---|
| GET | `/health`, `/ready` (outside `/api/v1`) |
| POST | `/auth/login` |
| GET | `/docs`, `/docs/oauth2-redirect`, `/redoc`, `/openapi.json`: only when `ENVIRONMENT` is `local`, `demo` or `test`; not served otherwise |

**Viewer (any signed-in user)**

`GET` on: `/auth/me`, `/mode`, `/overview`, `/dashboard/stats`, `/threat-intelligence/lookup`, `/simulation/status`, `/simulation/resources`, `/simulation/resources/{resource_id}`, `/simulation/events`, `/services`, `/services/{service_id}`, `/services/{service_id}/health`, `/incidents`, `/incidents/{incident_id}`, `/incidents/{incident_id}/timeline`, `/incidents/{incident_id}/investigations`, `/incidents/{incident_id}/recovery`, `/incidents/{incident_id}/verification`, `/incidents/{incident_id}/escalation`, `/escalations`, `/notifications`, `/recovery/actions`, `/recovery/executions`, `/ai/status`, `/demo/scenarios`.

**Operator**

| Method | Path | Why |
|---|---|---|
| POST | `/services/{service_id}/health` | Runs a health check |
| GET | `/integrations/status` | Probes cloud integrations with the server''s credentials |
| POST | `/incidents/{incident_id}/investigations` | Starts an investigation |
| POST | `/incidents/{incident_id}/under-investigation` | Changes incident state in the normal workflow |
| POST | `/incidents/{incident_id}/acknowledge` | Processes an escalation |
| POST | `/incidents/{incident_id}/recovery` | Executes a recovery action (medium/high risk needs the user''s own approval) |
| POST | `/incidents/{incident_id}/recovery/retry` | Retries a recovery action |

**Admin**

| Method | Path | Why |
|---|---|---|
| POST | `/services` | Registers a service (configuration) |
| PATCH | `/services/{service_id}` | Changes service configuration |
| PATCH | `/incidents/{incident_id}/state` | Manual state change, including manual resolution |
| POST | `/incidents/{incident_id}/recovery/approve` | Approves a medium/high-risk action |
| POST | `/incidents/{incident_id}/reject-recovery` | Rejects a proposed recovery |
| POST | `/simulation/start`, `/simulation/tick`, `/simulation/stop`, `/simulation/reset` | Simulation controls |
| POST | `/demo/services/{service_id}/fault`, `/demo/services/{service_id}/reset` | Fault injection and reset (isolated demo services only) |
| POST | `/ai/test` | Real authenticated request to the AI provider |