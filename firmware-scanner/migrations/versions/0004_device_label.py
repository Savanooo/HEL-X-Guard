"""Add device_label column to scans for firmware lineage grouping

Revision ID: 0004
Revises:     0003
Create Date: 2026-06-19
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("device_label", sa.String(128), nullable=True),
    )
    op.create_index("ix_scans_device_label", "scans", ["device_label"])


def downgrade() -> None:
    op.drop_index("ix_scans_device_label", "scans")
    op.drop_column("scans", "device_label")
