"""add user sessions table

Revision ID: d54564b0334d
Revises: d5930fde170c
Create Date: 2026-06-30 00:06:27.571134

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "d54564b0334d"
down_revision: Union[str, Sequence[str], None] = "d5930fde170c"
branch_labels = None
depends_on = None


def upgrade() -> None:

    op.create_table(
        "user_sessions",

        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),

        sa.Column(
            "user_id",
            sa.Integer(),
            nullable=False,
        ),

        sa.Column(
            "device_name",
            sa.String(),
            nullable=True,
        ),

        sa.Column(
            "ip_address",
            sa.String(),
            nullable=True,
        ),

        sa.Column(
            "user_agent",
            sa.String(),
            nullable=True,
        ),

        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),

        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),

        sa.Column(
            "last_active",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),

        sa.Column(
            "revoked_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),

        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),

        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "ix_user_sessions_user_id",
        "user_sessions",
        ["user_id"],
    )


def downgrade() -> None:

    op.drop_index(
        "ix_user_sessions_user_id",
        table_name="user_sessions",
    )

    op.drop_table("user_sessions")