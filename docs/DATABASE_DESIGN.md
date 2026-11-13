# CloudRescue X Database Design

## 1. Storage decisions

SQLAlchemy is the persistence boundary. SQLite is the local default, with migrations from the beginning. All timestamps are UTC. Foreign keys, unique constraints, indexes, and transaction boundaries are explicit. Audit events are append-only from the application perspective.

## 2. Entities

### users

`id`, `email`, `display_name`, `password_hash` or external subject, `is_active`, `created_at`, `updated_at`.

### roles and user_roles

Roles are `viewer`, `operator`, `administrator`, and restricted `demo_user`. A user may have multiple roles. Never store plaintext passwords.

### services

`id`, `name`, `environment`, `description`, `enabled`, `monitor_type`, `adapter_key`, `config_json`, `simulation_status`, `created_at`, `updated_at`, `version`.

### service_checks

`id`, `service_id`, `check_key`, `status`, `observed_at`, `latency_ms`, `details_json`, `adapter_key`, `correlation_id`, `created_at`.

Unique detection keys or a dedicated idempotency table prevent duplicate processing.

### incidents

`id`, `service_id`, `deduplication_key`, `state`, `severity`, `summary`, `opened_at`, `resolved_at`, `escalated_at`, `current_version`, `created_by`, `created_at`, `updated_at`.

Unique constraint: `(service_id, deduplication_key)` for the relevant detection window. State transitions are validated in domain code.

### evidence

`id`, `incident_id`, `source_type`, `source_ref`, `content_redacted`, `content_hash`, `observed_at`, `collected_at`, `trust_level`, `simulated`, `metadata_json`.

External text is treated as untrusted. Store redacted or bounded content and a hash where appropriate; do not persist secrets.

### investigations

`id`, `incident_id`, `provider_key`, `provider_version`, `status`, `input_evidence_hash`, `started_at`, `completed_at`, `error_code`, `result_json`, `simulated`, `correlation_id`.

### hypotheses

`id`, `investigation_id`, `code`, `statement`, `confidence`, `evidence_ids_json`, `missing_evidence_json`.

### recommendations

`id`, `incident_id`, `investigation_id`, `operation_type`, `parameters_json`, `rationale`, `risk_level`, `status`, `created_at`, `expires_at`.

### policy_decisions

`id`, `recommendation_id`, `policy_version`, `decision`, `reasons_json`, `required_approval`, `evaluated_by`, `evaluated_at`.

### recovery_actions

`id`, `incident_id`, `recommendation_id`, `operation_type`, `parameters_json`, `status`, `approved_by`, `started_at`, `completed_at`, `result_json`, `error_code`, `idempotency_key`, `adapter_key`, `simulated`.

Unique constraint on `(incident_id, idempotency_key)`.

### verifications

`id`, `incident_id`, `action_id`, `method`, `status`, `observations_json`, `started_at`, `completed_at`, `independent_adapter_key`, `simulated`.

### escalations

`id`, `incident_id`, `reason_code`, `severity`, `status`, `channel`, `recipient_ref`, `message_redacted`, `attempt_count`, `last_attempt_at`, `created_at`.

### audit_events

`id`, `incident_id`, `actor_type`, `actor_id`, `event_type`, `payload_json`, `correlation_id`, `occurred_at`, `prev_hash`, `event_hash`.

Hash chaining is optional for the first iteration but recommended for tamper-evident exports. No update/delete API should exist for audit records.

### integration_configs

`id`, `key`, `provider_type`, `enabled`, `simulation_status`, `config_json`, `secret_ref`, `last_tested_at`, `last_test_status`.

Secret values are never stored in `config_json`; only a reference to environment/secret-manager storage is allowed.

## 3. Relationships

`services 1:N service_checks`, `services 1:N incidents`, `incidents 1:N evidence`, `incidents 1:N investigations`, `investigations 1:N hypotheses`, `investigations 1:N recommendations`, `recommendations 1:N policy_decisions`, `incidents 1:N recovery_actions`, `recovery_actions 1:N verifications`, and `incidents 1:N escalations/audit_events`.

## 4. Indexes and retention

Index incident state/severity/opened time, service checks by service and observed time, timeline events by incident and occurred time, and audit events by actor and event type. Define retention only after organizer requirements are known; default local demo data may be reset explicitly.

