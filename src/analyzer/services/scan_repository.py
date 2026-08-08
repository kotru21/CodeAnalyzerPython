"""Persist and load scan results from Postgres (source of truth for async results)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import delete, select

from analyzer.api.schemas import AnalyzeResponse, Finding, ScanStats
from analyzer.models.finding import FindingModel
from analyzer.models.scan import Scan
from analyzer.utils.hash import md5_fingerprint

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

_TERMINAL_STATUSES = frozenset({"completed", "partial", "failed"})
_RUNNABLE_STATUSES = frozenset({"pending", "queued", "running"})


def create_scan(
    session: Session,
    *,
    scan_id: str,
    language: str = "javascript",
    source_hash: str = "",
    status: str = "pending",
) -> Scan:
    scan = Scan(
        id=scan_id,
        status=status,
        language=language,
        source_hash=source_hash,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def mark_running(session: Session, scan_id: str) -> bool:
    """Transition to running only from non-terminal states. Returns False if skipped."""
    scan = session.get(Scan, scan_id)
    if scan is None:
        return False
    if scan.status in _TERMINAL_STATUSES:
        return False
    if scan.status not in _RUNNABLE_STATUSES:
        return False
    scan.status = "running"
    scan.updated_at = datetime.now(UTC)
    session.commit()
    return True


def touch_scan(session: Session, scan_id: str) -> None:
    """Heartbeat updated_at so long-running scans are not marked stale."""
    scan = session.get(Scan, scan_id)
    if scan is None or scan.status in _TERMINAL_STATUSES:
        return
    scan.updated_at = datetime.now(UTC)
    session.commit()


def mark_failed(
    session: Session,
    scan_id: str,
    *,
    error_message: str,
    error_code: str = "task_failed",
) -> bool:
    """Mark failed only if not already completed/partial. Returns False if skipped."""
    scan = session.get(Scan, scan_id)
    if scan is None:
        return False
    if scan.status in ("completed", "partial"):
        return False
    scan.status = "failed"
    scan.error_message = error_message
    scan.error_code = error_code
    scan.updated_at = datetime.now(UTC)
    session.commit()
    return True


def fail_stale_scan(session: Session, scan_id: str, *, older_than_seconds: int) -> bool:
    """Mark a single pending/running scan failed if updated_at is past threshold."""
    if older_than_seconds <= 0:
        return False
    scan = session.get(Scan, scan_id)
    if scan is None or scan.status not in ("pending", "running", "queued"):
        return False
    cutoff = datetime.now(UTC) - timedelta(seconds=older_than_seconds)
    # Normalize naive datetimes from SQLite.
    updated = scan.updated_at
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=UTC)
    if updated >= cutoff:
        return False
    scan.status = "failed"
    scan.error_message = "scan timed out (stale worker / no completion)"
    scan.error_code = "scan_stale"
    scan.updated_at = datetime.now(UTC)
    session.commit()
    return True


def fail_stale_scans(session: Session, *, older_than_seconds: int) -> int:
    """Mark pending/running scans failed when updated_at is older than threshold."""
    if older_than_seconds <= 0:
        return 0
    cutoff = datetime.now(UTC) - timedelta(seconds=older_than_seconds)
    stmt = select(Scan).where(
        Scan.status.in_(("pending", "running", "queued")),
        Scan.updated_at < cutoff,
    )
    stale = list(session.scalars(stmt).all())
    now = datetime.now(UTC)
    for scan in stale:
        scan.status = "failed"
        scan.error_message = "scan timed out (stale worker / no completion)"
        scan.error_code = "scan_stale"
        scan.updated_at = now
    if stale:
        session.commit()
    return len(stale)


def save_analyze_response(session: Session, response: AnalyzeResponse) -> Scan:
    """Upsert scan row and replace findings from an AnalyzeResponse."""
    sid = str(response.scan_id)
    scan = session.get(Scan, sid)
    now = datetime.now(UTC)
    if scan is None:
        scan = Scan(
            id=sid,
            status=response.status,
            language=response.language,
            created_at=response.created_at,
            updated_at=now,
        )
        session.add(scan)
    else:
        scan.status = response.status
        scan.language = response.language
        scan.updated_at = now
        scan.error_message = None
        scan.error_code = None
        session.execute(delete(FindingModel).where(FindingModel.scan_id == sid))

    scan.total_findings = response.stats.total_findings
    scan.files_scanned = response.stats.files_scanned
    scan.lines_scanned = response.stats.lines_scanned
    scan.scan_duration_ms = response.stats.scan_duration_ms
    scan.failed_rules_json = json.dumps(list(response.failed_rules))

    for f in response.findings:
        fp = md5_fingerprint(f.rule_id, f.file_path, str(f.line_start), str(f.column or 0))
        session.add(
            FindingModel(
                scan_id=sid,
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                confidence=(
                    f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)
                ),
                file_path=f.file_path,
                line_start=f.line_start,
                line_end=f.line_end,
                column=f.column,
                code_snippet=f.code_snippet,
                description=f.description,
                remediation=f.remediation,
                cwe_id=f.cwe_id,
                owasp_category=f.owasp_category,
                fingerprint=fp,
            )
        )
    session.commit()
    session.refresh(scan)
    return scan


def get_scan(session: Session, scan_id: str) -> Scan | None:
    return session.get(Scan, scan_id)


def get_findings(session: Session, scan_id: str) -> list[FindingModel]:
    stmt = select(FindingModel).where(FindingModel.scan_id == scan_id)
    return list(session.scalars(stmt).all())


def scan_to_result_dict(session: Session, scan: Scan) -> dict[str, Any]:
    """Shape compatible with AnalyzeResponse / async poll JSON."""
    if scan.status in ("pending", "running", "queued"):
        st = "pending" if scan.status == "queued" else scan.status
        return {"status": st, "scan_id": scan.id}
    if scan.status == "failed":
        return {
            "status": "failed",
            "scan_id": scan.id,
            "error": scan.error_message or "task failed",
            "error_code": scan.error_code or "task_failed",
        }

    try:
        failed_rules = json.loads(scan.failed_rules_json or "[]")
        if not isinstance(failed_rules, list):
            failed_rules = []
        failed_rules = [str(x) for x in failed_rules]
    except json.JSONDecodeError:
        failed_rules = []

    rows = get_findings(session, scan.id)
    findings = [
        Finding(
            rule_id=f.rule_id,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            file_path=f.file_path,
            line_start=f.line_start,
            line_end=f.line_end,
            column=f.column,
            code_snippet=f.code_snippet,
            description=f.description,
            remediation=f.remediation,
            cwe_id=f.cwe_id,
            owasp_category=f.owasp_category,
        )
        for f in rows
    ]
    stats = ScanStats(
        total_findings=scan.total_findings,
        files_scanned=scan.files_scanned or 1,
        lines_scanned=scan.lines_scanned,
        scan_duration_ms=scan.scan_duration_ms,
        time_budget_exceeded=(scan.status == "partial"),
    )
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        key = sev.lower()
        if key == "critical":
            stats.critical += 1
        elif key == "high":
            stats.high += 1
        elif key == "medium":
            stats.medium += 1
        elif key == "low":
            stats.low += 1
        elif key == "info":
            stats.info += 1

    resp = AnalyzeResponse(
        scan_id=UUID(scan.id),
        status=scan.status,
        language=scan.language,
        stats=stats,
        findings=findings,
        created_at=scan.created_at,
        failed_rules=failed_rules,
    )
    return resp.model_dump(mode="json")
