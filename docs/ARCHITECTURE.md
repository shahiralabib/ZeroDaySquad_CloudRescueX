# CloudRescue X Architecture

## 1. Architectural style

CloudRescue X should begin as a modular monolith: one FastAPI backend process with separated domain, application, adapter, and API packages, plus a React/Vite frontend. This minimizes deployment and coordination overhead while keeping boundaries suitable for later service extraction.

The system is event-oriented inside the application. Long-running investigation, execution, and verification work should run through a durable job abstraction (initially an in-process/background worker with persisted job state; later Cloud Tasks or a queue). HTTP requests create commands and return resource state rather than holding open long operations.

```text
React/Vite UI
      |
Typed HTTP API (FastAPI/Pydantic)
      |
Application services / workflow orchestration
      |
Domain entities + policy engine + state machine
      |
SQLAlchemy repositories (SQLite locally)
      |
Adapters: local simulation/telemetry | local demo | Gemini | GCP monitoring/logging | notifications
```

The local simulation foundation persists a small infrastructure graph (web server, database
server, authentication service, firewall, and VPN gateway) and structured synthetic telemetry
in SQLite. Scenario generation is deterministic from a stored seed and marks every event with
`source=local_simulation` and `simulated=true`; it never claims to observe external resources.

## 2. Proposed directory structure

```text
CloudRescueX/
├── backend/
│   ├── pyproject.toml
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── logging.py
│   │   ├── api/
│   │   │   ├── deps.py
│   │   │   ├── errors.py
│   │   │   └── routes/
│   │   ├── domain/
│   │   │   ├── entities.py
│   │   │   ├── enums.py
│   │   │   ├── policies.py
│   │   │   └── state_machine.py
│   │   ├── application/
│   │   │   ├── incident_service.py
│   │   │   ├── investigation_service.py
│   │   │   ├── recovery_service.py
│   │   │   ├── verification_service.py
│   │   │   └── escalation_service.py
│   │   ├── schemas/
│   │   ├── infrastructure/
│   │   │   ├── database/
│   │   │   ├── repositories/
│   │   │   └── jobs/
│   │   └── adapters/
│   │       ├── contracts.py
│   │       ├── local/
│   │       ├── gemini/
│   │       ├── google_cloud/
│   │       └── notifications/
│   └── tests/
├── frontend/
│   ├── package.json
│   ├── src/
│   │   ├── app/
│   │   ├── components/
│   │   ├── features/
│   │   ├── pages/
│   │   ├── lib/
│   │   └── types/
│   └── tests/
├── demo/
│   ├── scenarios/
│   └── README.md
├── docs/
├── .env.example
├── docker-compose.yml
└── README.md
```

## 3. Backend responsibilities

- `api`: authentication, request validation, response serialization, pagination, and HTTP error mapping.
- `domain`: framework-independent entities, enums, transition rules, policy evaluation, and operation definitions.
- `application`: orchestrates use cases and transaction boundaries; it must not contain provider-specific SDK calls.
- `schemas`: input/output contracts, including the strict AI response schema.
- `infrastructure`: SQLAlchemy models, migrations, repositories, transaction management, and durable job execution.
- `adapters`: implementations of monitoring, evidence, AI, recovery, verification, and notifications interfaces.

All adapter calls receive correlation/context data and return typed results. Adapters must expose capability and simulation status so the UI can label them.

## 4. Frontend pages and components

Pages:

- **Dashboard**: service health summary, active incidents, recent actions, simulated-mode banner.
- **Services**: monitored services, status, last check, adapter/capability details.
- **Incident detail**: state, evidence, hypotheses, recommendations, policy results, actions, verification, escalation, timeline.
- **Incident history**: filterable/paginated resolved and escalated incidents.
- **Demo control**: trigger/reset only simulated scenarios; never available for real integrations.
- **Settings**: users/roles, policies, integrations, notification settings; administrator-only where applicable.
- **Login/access denied**: authentication and authorization states.

Reusable components include `StatusBadge`, `SimulationBanner`, `IncidentTimeline`, `EvidenceList`, `HypothesisCard`, `RecommendationCard`, `PolicyDecision`, `ApprovalDialog`, `ActionRunPanel`, `VerificationResult`, `EscalationPanel`, `AuditTable`, and `ErrorState`.

The frontend must not infer permissions from UI visibility alone; the backend remains authoritative.

## 5. Cross-cutting decisions

- UTC timestamps, UUID identifiers, and correlation IDs.
- Structured logs with event name, incident ID, actor ID, adapter, simulation flag, and outcome.
- Optimistic concurrency/version checks on incidents and actions.
- Idempotency keys for detection, action execution, and demo triggers.
- No provider SDK imports in domain code.
- Secrets loaded from environment variables locally and a managed secret store in deployment.

## 6. Deployment evolution

Local development uses SQLite and local adapters. A containerized deployment can run the frontend as static assets and the backend on Cloud Run behind HTTPS. SQLite is not suitable for multi-instance production; the persistence boundary should therefore support a later managed relational database, while Firestore remains a possible integration for selected event or configuration use cases. Google adapters stay disabled until credentials, IAM, network behavior, and integration tests are available.
