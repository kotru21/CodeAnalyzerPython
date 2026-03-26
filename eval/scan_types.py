from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NormalizedFinding:
    rule_id: str
    line: int | None = None
    path: str | None = None


@dataclass(frozen=True)
class BackendScanResult:
    ok: bool
    error: str | None
    raw: dict[str, Any]
    findings: list[NormalizedFinding]


def findings_from_analyzer_response(body: dict[str, Any]) -> list[NormalizedFinding]:
    raw = body.get("findings")
    if not isinstance(raw, list):
        return []
    out: list[NormalizedFinding] = []
    for f in raw:
        if not isinstance(f, dict):
            continue
        rid = f.get("rule_id")
        if not isinstance(rid, str):
            continue
        line = f.get("line")
        ln = int(line) if isinstance(line, int) else None
        fp = f.get("file_path")
        path: str | None = fp if isinstance(fp, str) else None
        out.append(NormalizedFinding(rule_id=rid, line=ln, path=path))
    return out


def analyzer_response_to_result(
    body: dict[str, Any] | None, error: str | None
) -> BackendScanResult:
    if error is not None:
        return BackendScanResult(ok=False, error=error, raw={}, findings=[])
    if body is None:
        return BackendScanResult(ok=False, error="empty body", raw={}, findings=[])
    return BackendScanResult(
        ok=True,
        error=None,
        raw=body,
        findings=findings_from_analyzer_response(body),
    )
