# CloudRescue X Security and Safety

## 1. Core safety rules

1. AI is advisory only. It cannot authorize or execute recovery.
2. Every operation must be a typed member of a versioned allowlist.
3. No AI-generated shell command, URL, resource ID, script, or arbitrary tool call may be executed.
4. Policy evaluation is deterministic, deny-by-default, and independent of AI.
5. Real infrastructure is disabled until an authenticated, explicitly configured adapter is enabled by an administrator.
6. Public/demo users can access simulated resources only.
7. Every decision, action, result, failure, and escalation is recorded in the timeline and audit trail.

## 2. Identity and authorization

Use short-lived access tokens, hashed local development passwords, secure refresh-token handling, and role checks at every privileged route. Enforce object-level authorization so a user cannot access another tenant/service if multi-tenancy is introduced. Administrator functions require administrator role and should support re-authentication for policy/integration changes.

## 3. Input and AI controls

- Bound evidence size and redact secrets, tokens, cookies, and authorization headers.
- Treat logs and external text as untrusted prompt content; delimit evidence and instruct providers not to follow embedded commands.
- Validate AI responses with strict Pydantic models, reject unknown operation types, reject unknown evidence IDs, and require bounded confidence values.
- Apply minimum evidence and confidence thresholds determined by policy, not by the model.
- Record provider name, model/version when applicable, prompt/input hash, simulated flag, and validation outcome.
- Never label deterministic local output as Gemini.

## 4. Recovery controls

The Phase 4 local catalog contains only `restart_demo_application`, `restore_known_good_configuration`, `restore_demo_dependency`, `scale_demo_application` (exactly one instance), and `reset_demo_environment`. Each operation has typed parameters, a demo-only target, bounded timeout, required permission, risk class, and approval rule.

Destructive operations, arbitrary scaling, credential changes, data deletion, network policy changes, and production operations are denied in the prototype. Recovery adapters must enforce the same allowlist at their boundary, not only in the API.

## 5. Execution and verification

The local engine prevents repeated completed/running execution for an incident/action pair, bounds execution with timeouts, records partial failures, and escalates failed attempts. Verification performs independent persisted health checks; an action response alone never resolves an incident.

## 6. Secrets and infrastructure

Provide `.env.example` with names and safe placeholders only. Never commit credentials. Local secrets stay in developer environment storage; hosted secrets use a managed secret store. Use least-privilege service identities, private configuration, HTTPS, secure headers, dependency scanning, and restricted CORS.

## 7. Logging and privacy

Emit structured logs with correlation IDs and outcomes, but never log tokens, passwords, full sensitive log payloads, or secret-bearing configuration. Redact before persistence and before sending evidence to any AI provider. Define incident/audit retention and deletion/export policy before production use.

## 8. Threat model highlights

Threats include prompt injection in logs, malformed AI output, replayed action requests, privilege escalation, SSRF through user-controlled endpoints, resource abuse, leaked credentials, duplicate recovery, and simulated/real mode confusion. Mitigations are bounded inputs, typed schemas, allowlists, RBAC, idempotency, adapter capability checks, explicit simulation banners, egress restrictions, rate limits, and independent verification.

## 9. Security testing gates

Before any real integration: dependency and secret scans, authentication/authorization tests, malformed-input tests, prompt-injection fixtures, policy bypass tests, replay/idempotency tests, audit integrity tests, and HTTPS/deployment configuration review.
