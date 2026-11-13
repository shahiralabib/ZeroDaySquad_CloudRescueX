# CloudRescue X Implementation Roadmap

The order below prioritizes a demonstrable local workflow before external integrations. No item implies completed functionality.

## Phase 0: Decisions and repository bootstrap

- Confirm authentication, initial scenarios, approval model, retention, and target Cloud Run constraints.
- Create backend/frontend manifests, environment template, formatting/linting, and database migration baseline.
- Establish typed API error and correlation-ID conventions.

## Phase 1: Domain and persistence

- Implement enums, entities, transition rules, operation catalog, and policy model.
- Implement SQLAlchemy models, repositories, migrations, and transaction helpers.
- Add audit event recording and idempotency persistence.
- Add unit tests for legal/illegal incident transitions and policy decisions.

## Phase 2: Local monitoring and incident detection

- Implement local simulated service adapter with visible simulation metadata.
- Implement health checks and deterministic failure scenarios.
- Implement idempotent incident creation and evidence capture.
- Add service, incident, evidence, and timeline API routes.

## Phase 3: Investigation

- Implement deterministic local investigation provider with explicit `local_deterministic` identity.
- Define strict investigation/recommendation schemas and validation.
- Add Gemini adapter interface and disabled/configuration-error behavior; do not claim live support until credentials and tests exist.
- Add investigation UI and tests for malformed/untrusted evidence.

## Phase 4: Safety and recovery

- Implement policy evaluation, approval recording, typed operation parameters, and action lifecycle.
- Implement local simulated recovery adapter.
- Add independent verification adapter and escalation on failure.
- Add action replay/idempotency, timeout, retry, and concurrency tests.

## Phase 5: Frontend demonstration

- Build dashboard, services, incident detail/timeline, history, demo control, settings, and access-control views.
- Add clear simulated-provider and simulated-service banners.
- Implement loading, empty, error, denied, and in-progress states.
- Add Playwright end-to-end happy path and negative paths.

## Phase 6: Administrator operations and notifications

- Add user/role administration, policy versioning, integration capability display, and audit filtering.
- Add local notification adapter (console/inbox) and escalation delivery status.
- Add rate limits, structured logging dashboards, and exportable incident records.

## Phase 7: External adapters and deployment readiness

- Implement Google Cloud Monitoring and Logging adapters behind existing contracts.
- Implement Gemini provider with credentials, model selection, schema validation, redaction, and integration tests.
- Validate IAM, secret management, network egress, HTTPS, Cloud Run health checks, and managed persistence.
- Keep each provider disabled unless configuration and capability tests pass.

## Testing strategy

- **Unit**: domain transitions, policies, redaction, schemas, idempotency, adapter fakes.
- **Integration**: FastAPI routes with SQLite, repository transactions, auth/RBAC, job state, audit trail.
- **Contract**: request/response JSON and error envelopes; provider adapter contract suite.
- **End-to-end**: Playwright local demo from trigger through verification/escalation.
- **Resilience**: duplicate detections, retries, timeouts, malformed AI output, unavailable providers, stale approvals.
- **Security**: authorization matrix, prompt injection, secret leakage, arbitrary-operation rejection, replay attacks.
- **Deployment**: container startup, health endpoints, HTTPS proxy behavior, environment validation.

## Risks and dependencies

| Risk/dependency | Impact | Mitigation |
|---|---|---|
| Google credentials/resources unavailable | Cloud adapters cannot be proven | Local adapters first; feature-gate and label cloud adapters |
| Gemini output variability | Unsafe or unusable recommendations | Strict schemas, evidence references, deterministic policy, fixtures |
| SQLite multi-instance limits | Unsafe hosted persistence | Keep repository boundary; move to managed database before scaling |
| Background work complexity | Lost or duplicate processing | Persist jobs/status, idempotency, bounded retries |
| Two-person team capacity | Scope creep | Modular monolith, narrow allowlist, vertical slices |
| Prompt injection in logs | Unsafe recommendations | Delimit/redact evidence and never execute model text |
| Credential/secret leakage | Compromise | Environment/secret references, redaction, scans |
| Demo/real confusion | Accidental real action | Capability metadata, UI banners, server-side simulation guards |
| Missing production requirements | Rework | Record open decisions and validate Cloud Run/IAM assumptions before integration |

## Recommended first vertical slice

Implement one local simulated service, one failure scenario, one evidence collector, deterministic investigation, one low-risk allowlisted recovery operation, independent verification, escalation on failure, and the complete incident timeline. Only after this slice is tested should the team add additional scenarios, Gemini, or Google Cloud adapters.

