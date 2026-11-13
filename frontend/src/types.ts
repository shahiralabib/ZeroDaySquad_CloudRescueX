export type Service = {
  id: number; name: string; description: string; status: string; environment: string;
  health_check_config: Record<string, unknown>; failure_threshold: number;
  simulation_status: boolean; updated_at: string | null; last_successful_check: string | null;
  last_failed_check: string | null; consecutive_failure_count: number;
  monitoring_interval_seconds: number; health_check_timeout_seconds: number;
};
export type HealthCheck = {
  id: number; service_id: number; status: string; response_time_ms: number;
  observed_at: string | null; error_message: string | null; evidence: Record<string, unknown>; simulated: boolean;
};
export type Incident = {
  id: number; service_id: number; service_name: string; incident_type: string; severity: string;
  state: string; summary: string; description: string; diagnostic_evidence: Record<string, unknown>;
  probable_root_cause: string | null; recovery_recommendation: string | null;
  recovery_outcome: string | null; verification_outcome: string | null; escalation_status: string;
  detection_timestamp: string | null; resolution_timestamp: string | null; is_demo: boolean;
  detection_rule: string; evidence_references: string[]; priority_score: number; priority_factors: Record<string, number>;
};
export type TimelineEvent = { id: number; incident_id: number; event_type: string; description: string; metadata: Record<string, unknown>; created_at: string | null };
export type Investigation = { id: number; incident_id: number; provider: string; status: string; simulated: boolean; confidence: number | null; result: InvestigationResult | null; error_code: string | null; created_at: string | null };
export type AlternativeHypothesis = { hypothesis: string; explanation: string; evidence_references: string[] };
/** Offline threat-intelligence finding stored in an incident's diagnostic evidence (local demo dataset, not a live feed). */
export type ThreatIntelligence = { indicator: string; observable?: string; matched: boolean; reputation: string; confidence: number; mitre_attack_techniques: string[]; description: string; source: string };
export type InvestigationResult = { summary: string; probable_root_cause: string; root_cause_explanation: string; evidence_references: string[]; alternative_hypotheses: AlternativeHypothesis[]; confidence_estimate: number; recommended_action: string; reason_for_recommendation: string; potential_risks: string[]; human_intervention_recommended: boolean };
export type RecoveryExecution = { id: number; incident_id: number; service_id: number; action_id: string; parameters: Record<string, unknown>; status: string; result: Record<string, unknown>; error_message: string | null; started_at: string | null; completed_at: string | null };
export type Verification = { id: number; incident_id: number; execution_id: number | null; outcome: string; successful_checks: number; required_checks: number; evidence: Record<string, unknown>; created_at: string | null };
export type Escalation = { id: number; incident_id: number; reason: string; severity: string; evidence: Record<string, unknown>; ai_findings: Record<string, unknown>; attempted_actions: unknown[]; policy_decisions: unknown[]; recommended_next_steps: string; acknowledged: boolean; assigned_administrator: string | null; escalated_at: string | null; acknowledged_at: string | null; status: "pending" | "acknowledged" | "rejected"; rejection_reason: string | null };
export type Notification = { id: number; incident_id: number | null; kind: string; severity: string; service_name: string; reason: string; dashboard_link: string; read: boolean; created_at: string | null };
export type ProviderStatus = { provider: string; configured: boolean; connected: boolean; simulated: boolean; message: string };
export type IntegrationStatus = { name: string; state: string; configured: boolean; connected: boolean; simulated: boolean; message: string };
export type DashboardStats = { total_services: number; healthy_services: number; active_incidents: number; resolved_incidents: number; failed_checks_last_hour: number; unhealthy_services: number; escalated_incidents: number; average_verified_recovery_seconds: number | null; severity_distribution: Record<string, number>; recovery_activity: { date: string; count: number }[]; detection_counts: Record<string, number>; mean_time_to_detect_seconds: number | null; recovery_success_rate: number | null };
export type Overview = { services: Service[]; incidents: Incident[]; metrics: { active_incidents: number; healthy_services: number; total_services: number }; seeded_demo_data: boolean };
export type RecoveryAction = { action_id: string; description: string; required_permissions: string[]; risk: string; timeout_seconds: number; allowed_parameters: string[]; preconditions: string[]; handler: string; rollback_strategy: string; verification_procedure: string };
