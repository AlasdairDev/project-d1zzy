"""Add filterable fields to listings (price_cents, condition, location_approx)

Revision ID: e7153433def1
Revises: 291b9966022f
Create Date: 2026-10-24 00:19:35.482470

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e7153433def1"
down_revision: str | None = "291b9966022f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add columns as nullable first
    op.add_column("listings", sa.Column("price_cents", sa.Integer(), nullable=True))
    op.add_column("listings", sa.Column("condition", sa.Text(), nullable=True))
    op.add_column("listings", sa.Column("location_approx", sa.Text(), nullable=True))

    # Create indexes
    op.create_index("idx_listings_price_cents", "listings", ["price_cents"])
    op.create_index("idx_listings_condition", "listings", ["condition"])
    op.create_index("idx_listings_location_approx", "listings", ["location_approx"])

    # Set default values for existing rows
    op.execute("UPDATE listings SET price_cents = 0 WHERE price_cents IS NULL")
    op.execute("UPDATE listings SET condition = 'good' WHERE condition IS NULL")
    op.execute("UPDATE listings SET location_approx = '' WHERE location_approx IS NULL")

    # Make columns non-nullable with defaults
    op.alter_column("listings", "price_cents", nullable=False, server_default="0")
    op.alter_column("listings", "condition", nullable=False, server_default="good")
    op.alter_column("listings", "location_approx", nullable=False, server_default="")


def downgrade() -> None:
    op.drop_index("idx_listings_price_cents", table_name="listings")
    op.drop_index("idx_listings_condition", table_name="listings")
    op.drop_index("idx_listings_location_approx", table_name="listings")
    op.drop_column("listings", "price_cents")
    op.drop_column("listings", "condition")
    op.drop_column("listings", "location_approx")
