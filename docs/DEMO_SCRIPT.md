# CloudRescue X Demo Script

## Preparation

1. Configure authentication (see [README.md](../README.md#authentication-and-roles)): create an admin user and, to show the roles, an operator and a viewer. Then start the backend and frontend using the PowerShell commands in the README.
2. Open `http://127.0.0.1:5173` and sign in as the admin user.
3. Confirm Settings shows the local deterministic AI provider as **Simulated** and Google integrations as **Not configured**.
4. Open Demo Control and identify the seeded isolated demo service.

## Healthy-to-recovery path

1. Reset the demo service to `healthy`.
2. Trigger `service_unavailable`.
3. Wait for the configured failure threshold. Monitoring, not a frontend timer, creates the incident.
4. Open Incidents and select the new incident.
5. Run the local investigation. It must show simulated provider labeling and evidence references.
6. Select the allowlisted low-risk restart action.
7. Execute it (an operator or admin may; the audit trail records who did).
8. Confirm the execution is followed by independent verification checks.
9. Confirm the incident becomes `RESOLVED` only after verification succeeds.
10. Refresh the page and confirm the incident timeline and recovery record remain persisted.

## Policy rejection and escalation path

1. Trigger `configuration_failure` or `dependency_unavailable`.
2. Run an investigation and choose an unsupported action ID, or submit an invalid parameter set through the API.
3. Confirm the policy returns a rejection and no recovery execution is created.
4. Open Escalations and confirm the escalation reason and policy decision.
5. Acknowledge the escalation as the signed-in operator or admin; it is recorded under that username.
6. Confirm the acknowledgement is present in the timeline and audit trail.

## Showing the roles (optional)

Sign in as the viewer: every page is readable and every action button is disabled. Sign in as the operator: investigations, health checks, acknowledgement and low-risk recovery are enabled; approvals, rejections and Demo Control stay disabled. The server enforces the same rules, so a disabled button cannot be bypassed from the browser.

All demo actions affect only the isolated simulated service. No real cloud resource is modified.
