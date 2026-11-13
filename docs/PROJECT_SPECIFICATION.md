# CloudRescue X Project Specification

## 1. Purpose

CloudRescue X is a local-first, AI-assisted cloud service resilience platform. It detects service failures, assembles diagnostic evidence, produces structured root-cause hypotheses and recovery recommendations, applies deterministic safety controls, executes only approved allowlisted actions, verifies restoration independently, and escalates unresolved incidents.

The initial product is a secure, repeatable prototype for a two-person university hackathon team. It must run on Windows 11 without Google Cloud or Gemini credentials. Any local simulation must be visibly labelled as simulated; deterministic local investigation must never be presented as Gemini output.

## 2. Goals

- Demonstrate the complete incident-to-recovery workflow locally.
- Persist incidents, evidence, decisions, actions, verification results, and audit events.
- Make AI advisory only: AI can analyze supplied evidence and recommend actions, never execute or authorize them.
- Enforce recovery through a small, explicit allowlist and deterministic policy engine.
- Support interchangeable local and future Google Cloud adapters.
- Provide administrator authentication and role-based protection for control-plane operations.
- Preserve idempotency, traceability, structured errors, and repeatable demos.
- Provide a migration path to HTTPS-hosted deployment on Cloud Run.

## 3. Non-goals for the prototype

- Direct control of arbitrary production infrastructure.
- Arbitrary shell commands, generated scripts, or unrestricted tool execution.
- Claiming Google Cloud Monitoring, Cloud Logging, Firestore, or Gemini support is operational before credentials and integration tests exist.
- Autonomous approval of destructive or high-risk actions.
- Public users controlling real infrastructure.
- Replacing a full observability, incident-management, or change-management platform.

## 4. Personas and roles

- **Viewer**: view dashboard, service status, incident details, and audit history.
- **Operator**: investigate incidents, request/review recommendations, and execute actions allowed by policy.
- **Administrator**: manage users, integrations, policies, demo scenarios, and escalation configuration.
- **Demo user**: access a restricted public demonstration surface containing simulated services only.

Authentication and authorization are mandatory for operator and administrator actions. The demo surface must not expose real adapters or privileged controls.

## 5. Functional requirements

1. Register monitored services with health-check and adapter configuration.
2. Poll or manually trigger health checks and create idempotent incidents for failures.
3. Capture diagnostic evidence with source, timestamp, correlation identifier, and trust metadata.
4. Investigate with Gemini when configured, otherwise use a clearly labelled deterministic local provider.
5. Validate AI output against strict Pydantic schemas and evidence-based confidence rules.
6. Produce recommendations that reference known allowlisted operation types.
7. Evaluate recommendations against deterministic policies before execution.
8. Execute only approved, typed operations through an adapter; never execute arbitrary command text.
9. Verify recovery through an independent health/behavior check.
10. Escalate when diagnosis, safety, execution, or verification cannot complete safely.
11. Display a chronological incident timeline and immutable audit events.
12. Configure integrations and safely reset controlled demo scenarios.

## 6. Quality attributes

- **Safety**: deny by default, least privilege, explicit approvals, bounded timeouts.
- **Reliability**: idempotent detection and processing, retry with caps, durable state.
- **Explainability**: every conclusion and action links to evidence and policy decisions.
- **Security**: secrets only in environment/secret stores, no secrets in logs, authenticated administration.
- **Portability**: adapter interfaces isolate local simulation from cloud providers.
- **Operability**: structured JSON logs, correlation IDs, health endpoints, clear simulated labels.
- **Testability**: deterministic fixtures, fake adapters, API contract tests, Playwright workflows.

## 7. Definition of done for the prototype

The prototype is complete only when a judge can run it locally, trigger a labelled simulated failure, observe evidence and an investigation, see a policy decision, execute a safe simulated recovery, observe independent verification, and inspect the complete timeline. Tests must cover denied actions, malformed AI output, duplicate detection, failed recovery, escalation, and authorization boundaries.

## 8. Open product decisions

- Exact authentication mechanism for the first local build (recommended: local JWT with seeded development users, replaced or integrated with an identity provider later).
- Whether approval is always manual in the prototype or can be configured for low-risk demo actions (recommended: manual operator approval by default).
- The initial simulated service scenarios and operation catalog.
- Retention and export requirements for audit records.
- Target Google Cloud project, region, and production identity provider once organizer resources exist.

