"""Normalize legacy incident states for the Phase 2 state machine."""

from typing import Sequence, Union

from alembic import op

revision: str = "0004_normalize_legacy_states"
down_revision: Union[str, None] = "0003_ai_investigations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE incidents
        SET state = CASE lower(state)
            WHEN 'open' THEN 'DETECTED'
            WHEN 'investigating' THEN 'INVESTIGATING'
            WHEN 'awaiting_approval' THEN 'AWAITING_APPROVAL'
            WHEN 'recovering' THEN 'RECOVERING'
            WHEN 'verifying' THEN 'VERIFYING'
            WHEN 'resolved' THEN 'RESOLVED'
            WHEN 'escalated' THEN 'ESCALATED'
            WHEN 'failed' THEN 'FAILED'
            ELSE state
        END
        """
    )


def downgrade() -> None:
    pass
