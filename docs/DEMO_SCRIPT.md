# CloudRescue X Demo Script

## Preparation

1. Start the backend and frontend using the PowerShell commands in [README.md](../README.md).
2. Open `http://127.0.0.1:5173`.
3. Confirm Settings shows the local deterministic AI provider as **Simulated** and Google integrations as **Not configured**.
4. Open Demo Control and identify the seeded isolated demo service.

## Healthy-to-recovery path

1. Reset the demo service to `healthy`.
2. Trigger `service_unavailable`.
3. Wait for the configured failure threshold. Monitoring, not a frontend timer, creates the incident.
4. Open Incidents and select the new incident.
5. Run the local investigation. It must show simulated provider labeling and evidence references.
6. Select the allowlisted low-risk restart action.
7. Execute it with administrator authorization.
8. Confirm the execution is followed by independent verification checks.
9. Confirm the incident becomes `RESOLVED` only after verification succeeds.
10. Refresh the page and confirm the incident timeline and recovery record remain persisted.

## Policy rejection and escalation path

1. Trigger `configuration_failure` or `dependency_unavailable`.
2. Run an investigation and choose an unsupported action ID, or submit an invalid parameter set through the API.
3. Confirm the policy returns a rejection and no recovery execution is created.
4. Open Escalations and confirm the escalation reason and policy decision.
5. Acknowledge the escalation as the local administrator.
6. Confirm the acknowledgement is present in the timeline and audit trail.

All demo actions affect only the isolated simulated service. No real cloud resource is modified.
