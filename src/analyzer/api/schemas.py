from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from analyzer.core.severity import Confidence, Severity


class ScanConfig(BaseModel):
    enable_taint: bool = True
    severity_threshold: Severity = Severity.LOW
    rule_ids: list[str] | None = None


class AnalyzeRequest(BaseModel):
    source_code: str = Field(..., min_length=1, max_length=5_000_000)
    file_path: str = Field(default="untitled.js")
    language: str | None = Field(
        default=None,
        description="Force language; auto-detected if omitted",
    )
    config: ScanConfig = Field(default_factory=ScanConfig)
    scan_id: UUID | None = Field(
        default=None,
        description="When set (e.g. async worker), used as report id instead of a new UUID",
    )
    response_format: Literal["json", "sarif"] = "json"


class FindingLocation(BaseModel):
    file_path: str
    line_start: int
    line_end: int
    column: int | None = None


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    file_path: str
    line_start: int
    line_end: int
    column: int | None = None
    code_snippet: str
    description: str
    remediation: str
    cwe_id: str
    owasp_category: str


class ScanStats(BaseModel):
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    files_scanned: int = 0
    lines_scanned: int = 0
    scan_duration_ms: int = 0
    time_budget_exceeded: bool = False


class AnalyzeResponse(BaseModel):
    scan_id: UUID
    status: str
    language: str
    stats: ScanStats
    findings: list[Finding]
    created_at: datetime
    failed_rules: list[str] = Field(default_factory=list)


class AsyncAnalyzeResponse(BaseModel):
    task_id: str
    scan_id: UUID
    status: str
    poll_url: str


class RuleInfo(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    cwe_id: str
    owasp: str
    description: str


class HealthResponse(BaseModel):
    status: str
    version: str
    rules_loaded: int
