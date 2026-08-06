"""Migrate password verification to sha-256

Revision ID: e68ecfbf891c
Revises: 156ee0806e44
Create Date: 2026-08-06 09:28:08.926160

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e68ecfbf891c'
down_revision: Union[str, Sequence[str], None] = '156ee0806e44'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:

    op.execute("DELETE FROM password_reset")

    op.alter_column(
        "password_reset",
        "hashed_token",
        new_column_name="token_hash",
        existing_type=sa.String(),
    )

    op.alter_column(
        "password_reset",
        "token_hash",
        existing_type=sa.String(),
        type_=sa.String(length=64),
        nullable=False,
    )

    op.create_index(
        "ix_password_reset_token_hash",
        "password_reset",
        ["token_hash"],
        unique=False,
    )

    op.create_unique_constraint(
        "uq_password_reset_token_hash",
        "password_reset",
        ["token_hash"],
    )


def downgrade() -> None:

    op.drop_constraint(
        "uq_password_reset_token_hash",
        "password_reset",
        type_="unique",
    )

    op.drop_index(
        "ix_password_reset_token_hash",
        table_name="password_reset",
    )

    op.alter_column(
        "password_reset",
        "token_hash",
        existing_type=sa.String(length=64),
        type_=sa.String(),
        nullable=True,
    )

    op.alter_column(
        "password_reset",
        "token_hash",
        new_column_name="hashed_token",
        existing_type=sa.String(),
    )
