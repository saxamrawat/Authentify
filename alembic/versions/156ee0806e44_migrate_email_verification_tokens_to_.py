"""Migrate email verification tokens to sha256

Revision ID: 156ee0806e44
Revises: f33e875b3626
Create Date: 2026-08-05 09:41:03.488341

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '156ee0806e44'
down_revision: Union[str, Sequence[str], None] = 'f33e875b3626'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    # Existing bcrypt-based verification tokens are incompatible
    # with the new SHA-256 lookup mechanism.
    op.execute("DELETE FROM email_verification")

    # Rename the column
    op.alter_column(
        "email_verification",
        "hashed_token",
        new_column_name="token_hash",
        existing_type=sa.String(),
    )

    # Update the column definition
    op.alter_column(
        "email_verification",
        "token_hash",
        existing_type=sa.String(),
        type_=sa.String(length=64),
        nullable=False,
    )

    # Create index
    op.create_index(
        "ix_email_verification_token_hash",
        "email_verification",
        ["token_hash"],
        unique=False,
    )

    # Create unique constraint
    op.create_unique_constraint(
        "uq_email_verification_token_hash",
        "email_verification",
        ["token_hash"],
    )


def downgrade() -> None:
    """Downgrade schema."""

    op.drop_constraint(
        "uq_email_verification_token_hash",
        "email_verification",
        type_="unique",
    )

    op.drop_index(
        "ix_email_verification_token_hash",
        table_name="email_verification",
    )

    op.alter_column(
        "email_verification",
        "token_hash",
        existing_type=sa.String(length=64),
        type_=sa.String(),
        nullable=True,
    )

    op.alter_column(
        "email_verification",
        "token_hash",
        new_column_name="hashed_token",
        existing_type=sa.String(),
    )