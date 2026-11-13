"""Add local infrastructure simulation and telemetry."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0007_local_simulation_telemetry"
down_revision: Union[str, None] = "0006_recovery_approvals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "infrastructure_resources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("resource_key", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("resource_type", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="healthy"),
        sa.Column("environment", sa.String(length=32), nullable=False, server_default="local_simulation"),
        sa.Column("configuration_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("parent_resource_id", sa.Integer(), sa.ForeignKey("infrastructure_resources.id"), nullable=True),
        sa.Column("simulated", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_infrastructure_resources_resource_key", "infrastructure_resources", ["resource_key"], unique=True)
    op.create_index("ix_infrastructure_resources_resource_type", "infrastructure_resources", ["resource_type"])
    op.create_index("ix_infrastructure_resources_parent_resource_id", "infrastructure_resources", ["parent_resource_id"])

    op.create_table(
        "simulation_states",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scenario", sa.String(length=64), nullable=False, server_default="baseline"),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="stopped"),
        sa.Column("seed", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("tick_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stopped_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "telemetry_events",
        sa.Column("event_id", sa.String(length=36), primary_key=True),
        sa.Column("resource_id", sa.Integer(), sa.ForeignKey("infrastructure_resources.id"), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False, server_default="local_simulation"),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("correlation_id", sa.String(length=36), nullable=True),
        sa.Column("simulated", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index("ix_telemetry_events_resource_id", "telemetry_events", ["resource_id"])
    op.create_index("ix_telemetry_events_category", "telemetry_events", ["category"])
    op.create_index("ix_telemetry_events_event_type", "telemetry_events", ["event_type"])
    op.create_index("ix_telemetry_events_severity", "telemetry_events", ["severity"])
    op.create_index("ix_telemetry_events_observed_at", "telemetry_events", ["observed_at"])
    op.create_index("ix_telemetry_events_correlation_id", "telemetry_events", ["correlation_id"])


def downgrade() -> None:
    op.drop_index("ix_telemetry_events_correlation_id", table_name="telemetry_events")
    op.drop_index("ix_telemetry_events_observed_at", table_name="telemetry_events")
    op.drop_index("ix_telemetry_events_severity", table_name="telemetry_events")
    op.drop_index("ix_telemetry_events_event_type", table_name="telemetry_events")
    op.drop_index("ix_telemetry_events_category", table_name="telemetry_events")
    op.drop_index("ix_telemetry_events_resource_id", table_name="telemetry_events")
    op.drop_table("telemetry_events")
    op.drop_table("simulation_states")
    op.drop_index("ix_infrastructure_resources_parent_resource_id", table_name="infrastructure_resources")
    op.drop_index("ix_infrastructure_resources_resource_type", table_name="infrastructure_resources")
    op.drop_index("ix_infrastructure_resources_resource_key", table_name="infrastructure_resources")
    op.drop_table("infrastructure_resources")
