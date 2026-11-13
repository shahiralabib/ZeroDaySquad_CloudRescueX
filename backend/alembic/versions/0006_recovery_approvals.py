"""Add one-time recovery approvals."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0006_recovery_approvals"
down_revision: Union[str, None] = "0005_recovery_escalation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "recovery_approvals",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("action_id", sa.String(length=80), nullable=False),
        sa.Column("parameters_hash", sa.String(length=64), nullable=False),
        sa.Column("approver_principal", sa.String(length=120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_recovery_approvals_incident_id", "recovery_approvals", ["incident_id"])
    op.create_index("ix_recovery_approvals_parameters_hash", "recovery_approvals", ["parameters_hash"])


def downgrade() -> None:
    op.drop_index("ix_recovery_approvals_parameters_hash", table_name="recovery_approvals")
    op.drop_index("ix_recovery_approvals_incident_id", table_name="recovery_approvals")
    op.drop_table("recovery_approvals")
