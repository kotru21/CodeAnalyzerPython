from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from analyzer.core.language_detect import SUPPORTED_LANGUAGES
from analyzer.core.severity import Confidence, Severity
from analyzer.utils.text import sanitize_lone_surrogates


def _validate_language(v: str | None) -> str | None:
    if v is not None and v not in SUPPORTED_LANGUAGES:
        msg = f"unsupported language: {v!r} (supported: {sorted(SUPPORTED_LANGUAGES)})"
        raise ValueError(msg)
    return v


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

    @field_validator("source_code", "file_path", mode="before")
    @classmethod
    def _sanitize_text(cls, v: object) -> object:
        # mode="before": core str validation rejects lone surrogates outright.
        if isinstance(v, str):
            return sanitize_lone_surrogates(v)
        return v

    @field_validator("language")
    @classmethod
    def _check_language(cls, v: str | None) -> str | None:
        return _validate_language(v)


class AnalyzeBundleRequest(BaseModel):
    """Multi-file scan: per-file fn index + relative imports; rules run per file."""

    files: dict[str, str] = Field(
        ...,
        description="Relative path → source text (UTF-8). Paths should use forward slashes.",
    )
    language: str | None = Field(
        default=None,
        description="Force language for all files; else inferred from each path",
    )
    config: ScanConfig = Field(default_factory=ScanConfig)
    scan_id: UUID | None = None
    response_format: Literal["json", "sarif"] = "json"
    tsconfig_paths: dict[str, list[str]] | None = Field(
        default=None,
        description="Optional TS path aliases, e.g. {'@app/*': ['src/*']}",
    )

    @field_validator("files", mode="before")
    @classmethod
    def _sanitize_files(cls, v: object) -> object:
        if not isinstance(v, dict):
            return v
        sanitized: dict[object, object] = {}
        original_paths: dict[object, object] = {}
        for original_path, source in v.items():
            path = (
                sanitize_lone_surrogates(original_path)
                if isinstance(original_path, str)
                else original_path
            )
            if path in original_paths and original_paths[path] != original_path:
                msg = f"bundle paths collide after sanitization: {path!r}"
                raise ValueError(msg)
            original_paths[path] = original_path
            sanitized[path] = (
                sanitize_lone_surrogates(source) if isinstance(source, str) else source
            )
        return sanitized

    @field_validator("files")
    @classmethod
    def nonempty_files(cls, v: dict[str, str]) -> dict[str, str]:
        if not v:
            msg = "files must contain at least one entry"
            raise ValueError(msg)
        return v

    @field_validator("language")
    @classmethod
    def _check_language(cls, v: str | None) -> str | None:
        return _validate_language(v)


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
    status: Literal["completed", "partial", "failed"]
    language: str
    stats: ScanStats
    findings: list[Finding]
    created_at: datetime
    failed_rules: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


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
    database: Literal["ok", "unavailable"] = "ok"
