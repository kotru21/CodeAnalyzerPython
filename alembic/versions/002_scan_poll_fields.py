"""add files_scanned and failed_rules_json to scans

Revision ID: 002_poll_fields
Revises: 001_initial
Create Date: 2026-08-08
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "002_poll_fields"
down_revision: str | None = "001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("files_scanned", sa.Integer(), nullable=False, server_default="1"),
    )
    op.add_column(
        "scans",
        sa.Column("failed_rules_json", sa.Text(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("scans", "failed_rules_json")
    op.drop_column("scans", "files_scanned")
