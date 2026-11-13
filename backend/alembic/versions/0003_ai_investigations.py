"""Add persisted AI investigation results."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003_ai_investigations"
down_revision: Union[str, None] = "0002_phase2_incident_management"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("simulated", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("result_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_investigations_incident_id", "investigations", ["incident_id"])


def downgrade() -> None:
    op.drop_index("ix_investigations_incident_id", table_name="investigations")
    op.drop_table("investigations")
