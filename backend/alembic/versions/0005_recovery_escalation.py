"""Add recovery, verification, escalation, and notification records."""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0005_recovery_escalation"
down_revision: Union[str, None] = "0004_normalize_legacy_states"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table("recovery_executions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("service_id", sa.Integer(), sa.ForeignKey("services.id"), nullable=False),
        sa.Column("action_id", sa.String(80), nullable=False),
        sa.Column("parameters_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("status", sa.String(32), nullable=False, server_default="started"),
        sa.Column("result_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_recovery_executions_incident_id", "recovery_executions", ["incident_id"])
    op.create_index("ix_recovery_executions_service_id", "recovery_executions", ["service_id"])
    op.create_table("verification_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("execution_id", sa.Integer(), sa.ForeignKey("recovery_executions.id"), nullable=True),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("successful_checks", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("required_checks", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("evidence_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_verification_attempts_incident_id", "verification_attempts", ["incident_id"])
    op.create_table("escalations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("ai_findings_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("attempted_actions_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("policy_decisions_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("recommended_next_steps", sa.Text(), nullable=False, server_default=""),
        sa.Column("acknowledged", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("assigned_administrator", sa.String(120), nullable=True),
        sa.Column("escalated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_escalations_incident_id", "escalations", ["incident_id"])
    op.create_table("notifications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=True),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("service_name", sa.String(120), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("dashboard_link", sa.String(240), nullable=False),
        sa.Column("deduplication_key", sa.String(200), nullable=False),
        sa.Column("read", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_notifications_incident_id", "notifications", ["incident_id"])
    op.create_index("ix_notifications_deduplication_key", "notifications", ["deduplication_key"])


def downgrade() -> None:
    op.drop_table("notifications")
    op.drop_table("escalations")
    op.drop_table("verification_attempts")
    op.drop_table("recovery_executions")
