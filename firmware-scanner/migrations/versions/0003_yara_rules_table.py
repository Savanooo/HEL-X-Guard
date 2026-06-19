"""Add yara_rules table for user-managed YARA rules

Revision ID: 0003
Revises:     0002
Create Date: 2026-06-19
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "yara_rules",
        sa.Column("id",          sa.String(36),  primary_key=True),
        sa.Column("name",        sa.String(128), nullable=False, unique=True),
        sa.Column("description", sa.Text,        nullable=False, server_default=""),
        sa.Column("severity",    sa.String(16),  nullable=False, server_default="medium"),
        sa.Column("content",     sa.Text,        nullable=False),
        sa.Column("enabled",     sa.Boolean,     nullable=False, server_default="1"),
        sa.Column("created_by",  sa.String(64),  nullable=False, server_default=""),
        sa.Column("created_at",  sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at",  sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_yara_rules_name", "yara_rules", ["name"])


def downgrade() -> None:
    op.drop_index("ix_yara_rules_name", "yara_rules")
    op.drop_table("yara_rules")
