import uuid

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from analyzer.models.base import Base


class FindingModel(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default_factory=lambda: str(uuid.uuid4())
    )
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"))
    rule_id: Mapped[str] = mapped_column(String(30), default="")
    severity: Mapped[str] = mapped_column(String(10), default="")
    confidence: Mapped[str] = mapped_column(String(10), default="")
    file_path: Mapped[str] = mapped_column(String(500), default="")
    line_start: Mapped[int] = mapped_column(Integer, default=0)
    line_end: Mapped[int] = mapped_column(Integer, default=0)
    column: Mapped[int | None] = mapped_column(Integer, default=None)
    code_snippet: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    cwe_id: Mapped[str] = mapped_column(String(20), default="")
    owasp_category: Mapped[str] = mapped_column(String(60), default="")
    fingerprint: Mapped[str] = mapped_column(String(32), default="")
