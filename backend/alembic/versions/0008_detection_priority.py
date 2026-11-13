"""Add explainable detection and incident priority fields."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0008_detection_priority"
down_revision: Union[str, None] = "0007_local_simulation_telemetry"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "incidents",
        sa.Column("detection_rule", sa.String(length=120), nullable=False, server_default="health_check_failure"),
    )
    op.add_column("incidents", sa.Column("evidence_references_json", sa.Text(), nullable=False, server_default="[]"))
    op.add_column("incidents", sa.Column("priority_score", sa.Float(), nullable=False, server_default="0"))
    op.add_column("incidents", sa.Column("priority_factors_json", sa.Text(), nullable=False, server_default="{}"))
    op.create_index("ix_incidents_detection_rule", "incidents", ["detection_rule"])


def downgrade() -> None:
    op.drop_index("ix_incidents_detection_rule", table_name="incidents")
    op.drop_column("incidents", "priority_factors_json")
    op.drop_column("incidents", "priority_score")
    op.drop_column("incidents", "evidence_references_json")
    op.drop_column("incidents", "detection_rule")
