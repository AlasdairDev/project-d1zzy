"""Make moderation_actions append-only

Revision ID: b7c1d2e3f4a5
Revises: 6341ed90600f
Create Date: 2026-11-16 00:00:00.000000
"""

from collections.abc import Sequence

from alembic import op

revision: str = "b7c1d2e3f4a5"
down_revision: str | None = "6341ed90600f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION deny_moderation_action_change()
        RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'moderation_actions is append-only';
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER moderation_actions_no_update
        BEFORE UPDATE OR DELETE ON moderation_actions
        FOR EACH ROW EXECUTE FUNCTION deny_moderation_action_change();
        """
    )
    op.execute(
        """
        CREATE TRIGGER moderation_actions_no_truncate
        BEFORE TRUNCATE ON moderation_actions
        FOR EACH STATEMENT EXECUTE FUNCTION deny_moderation_action_change();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS moderation_actions_no_truncate ON moderation_actions")
    op.execute("DROP TRIGGER IF EXISTS moderation_actions_no_update ON moderation_actions")
    op.execute("DROP FUNCTION IF EXISTS deny_moderation_action_change()")
