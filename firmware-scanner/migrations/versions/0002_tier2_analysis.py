"""Add Tier 2 analysis columns — CVE match and disassembly stats

Revision ID: 0002
Revises:     0001
Create Date: 2026-06-18
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("cve_status",    sa.String(16), nullable=True))
    op.add_column("scans", sa.Column("cve_json",      sa.Text,       nullable=True))
    op.add_column("scans", sa.Column("cve_error",     sa.Text,       nullable=True))
    op.add_column("scans", sa.Column("disasm_status", sa.String(16), nullable=True))
    op.add_column("scans", sa.Column("disasm_json",   sa.Text,       nullable=True))
    op.add_column("scans", sa.Column("disasm_error",  sa.Text,       nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "disasm_error")
    op.drop_column("scans", "disasm_json")
    op.drop_column("scans", "disasm_status")
    op.drop_column("scans", "cve_error")
    op.drop_column("scans", "cve_json")
    op.drop_column("scans", "cve_status")
