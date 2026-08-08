import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from analyzer.models.base import Base


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_created_at", "created_at"),)

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default_factory=lambda: str(uuid.uuid4())
    )
    status: Mapped[str] = mapped_column(String(20), default="pending")
    language: Mapped[str] = mapped_column(String(20), default="javascript")
    source_hash: Mapped[str] = mapped_column(String(64), default="")
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    files_scanned: Mapped[int] = mapped_column(Integer, default=1)
    lines_scanned: Mapped[int] = mapped_column(Integer, default=0)
    scan_duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    failed_rules_json: Mapped[str] = mapped_column(Text, default="[]")
    error_message: Mapped[str | None] = mapped_column(Text, default=None)
    error_code: Mapped[str | None] = mapped_column(String(64), default=None)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default_factory=lambda: datetime.now(UTC),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default_factory=lambda: datetime.now(UTC),
    )
