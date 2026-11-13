"""Add Phase 2 monitoring and incident management tables."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_phase2_incident_management"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("services", sa.Column("description", sa.Text(), nullable=False, server_default=""))
    op.add_column("services", sa.Column("health_check_config", sa.Text(), nullable=False, server_default="{}"))
    op.add_column("services", sa.Column("health_check_timeout_seconds", sa.Float(), nullable=False, server_default="2.0"))
    op.add_column("services", sa.Column("failure_threshold", sa.Integer(), nullable=False, server_default="2"))
    op.add_column("services", sa.Column("monitoring_interval_seconds", sa.Integer(), nullable=False, server_default="30"))
    op.add_column("services", sa.Column("consecutive_failure_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("services", sa.Column("last_successful_check", sa.DateTime(timezone=True), nullable=True))
    op.add_column("services", sa.Column("last_failed_check", sa.DateTime(timezone=True), nullable=True))

    op.add_column("incidents", sa.Column("incident_type", sa.String(length=64), nullable=False, server_default="service_unavailable"))
    op.add_column("incidents", sa.Column("description", sa.Text(), nullable=False, server_default=""))
    op.add_column("incidents", sa.Column("diagnostic_evidence", sa.Text(), nullable=False, server_default="{}"))
    op.add_column("incidents", sa.Column("probable_root_cause", sa.Text(), nullable=True))
    op.add_column("incidents", sa.Column("recovery_recommendation", sa.Text(), nullable=True))
    op.add_column("incidents", sa.Column("recovery_outcome", sa.Text(), nullable=True))
    op.add_column("incidents", sa.Column("verification_outcome", sa.Text(), nullable=True))
    op.add_column("incidents", sa.Column("escalation_status", sa.String(length=32), nullable=False, server_default="not_escalated"))
    op.add_column("incidents", sa.Column("detection_timestamp", sa.DateTime(timezone=True), nullable=True))
    op.add_column("incidents", sa.Column("resolution_timestamp", sa.DateTime(timezone=True), nullable=True))
    op.add_column("incidents", sa.Column("deduplication_key", sa.String(length=160), nullable=True))
    op.execute("UPDATE incidents SET detection_timestamp = created_at WHERE detection_timestamp IS NULL")
    op.execute("UPDATE incidents SET deduplication_key = 'legacy:' || id WHERE deduplication_key IS NULL")
    with op.batch_alter_table("incidents") as batch:
        batch.alter_column("detection_timestamp", nullable=False)
        batch.alter_column("deduplication_key", nullable=False)
        batch.create_index("ix_incidents_deduplication_key", ["deduplication_key"])

    op.create_table(
        "health_checks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("service_id", sa.Integer(), sa.ForeignKey("services.id"), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("response_time_ms", sa.Float(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("simulated", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index("ix_health_checks_service_id", "health_checks", ["service_id"])
    op.create_table(
        "incident_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_incident_events_incident_id", "incident_events", ["incident_id"])
    op.create_table(
        "demo_faults",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("service_id", sa.Integer(), sa.ForeignKey("services.id"), nullable=False, unique=True),
        sa.Column("scenario", sa.String(length=64), nullable=False, server_default="healthy"),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("demo_faults")
    op.drop_index("ix_incident_events_incident_id", table_name="incident_events")
    op.drop_table("incident_events")
    op.drop_index("ix_health_checks_service_id", table_name="health_checks")
    op.drop_table("health_checks")
    with op.batch_alter_table("incidents") as batch:
        batch.drop_index("ix_incidents_deduplication_key")
        for column in ["deduplication_key", "resolution_timestamp", "detection_timestamp", "escalation_status", "verification_outcome", "recovery_outcome", "recovery_recommendation", "probable_root_cause", "diagnostic_evidence", "description", "incident_type"]:
            batch.drop_column(column)
    for column in ["last_failed_check", "last_successful_check", "consecutive_failure_count", "monitoring_interval_seconds", "failure_threshold", "health_check_timeout_seconds", "health_check_config", "description"]:
        op.drop_column("services", column)

