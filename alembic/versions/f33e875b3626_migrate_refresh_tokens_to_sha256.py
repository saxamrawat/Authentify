"""Migrate refresh tokens to sha256

Revision ID: f33e875b3626
Revises: 1d8eac4bc74d
Create Date: 2026-08-04 08:37:15.876662

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f33e875b3626'
down_revision: Union[str, Sequence[str], None] = '1d8eac4bc74d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    # Existing bcrypt-based refresh tokens are not compatible with
    # the new SHA-256 lookup mechanism.
    op.execute("DELETE FROM refresh_tokens")

    # Rename the column
    op.alter_column(
        "refresh_tokens",
        "hashed_token",
        new_column_name="token_hash",
        existing_type=sa.String(),
    )

    # Update the column definition
    op.alter_column(
        "refresh_tokens",
        "token_hash",
        existing_type=sa.String(),
        type_=sa.String(length=64),
        nullable=False,
    )

    # Create index
    op.create_index(
        "ix_refresh_tokens_token_hash",
        "refresh_tokens",
        ["token_hash"],
        unique=False,
    )

    # Create unique constraint
    op.create_unique_constraint(
        "uq_refresh_tokens_token_hash",
        "refresh_tokens",
        ["token_hash"],
    )


def downgrade() -> None:
    """Downgrade schema."""

    op.drop_constraint(
        "uq_refresh_tokens_token_hash",
        "refresh_tokens",
        type_="unique",
    )

    op.drop_index(
        "ix_refresh_tokens_token_hash",
        table_name="refresh_tokens",
    )

    op.alter_column(
        "refresh_tokens",
        "token_hash",
        existing_type=sa.String(length=64),
        type_=sa.String(),
        nullable=True,
    )

    op.alter_column(
        "refresh_tokens",
        "token_hash",
        new_column_name="hashed_token",
        existing_type=sa.String(),
    )
