from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from analyzer.core.severity import Severity

if TYPE_CHECKING:
    from analyzer.api.schemas import AnalyzeResponse


def _severity_to_level(severity: Severity) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _artifact_uri(file_path: str) -> str:
    if "://" in file_path:
        return file_path
    return quote(file_path, safe="/\\:")


def build_sarif_log(
    analyze_response: AnalyzeResponse,
    *,
    tool_name: str,
    tool_version: str,
    information_uri: str | None = None,
) -> dict[str, Any]:
    """Build a minimal SARIF 2.1.0 log dict from an analyze response."""
    from analyzer.rules.registry import get_all_rules

    rules_payload: list[dict[str, Any]] = []
    for rule in get_all_rules():
        meta = rule.meta()
        if not meta.rule_id.startswith("JS-"):
            continue
        rules_payload.append(
            {
                "id": meta.rule_id,
                "name": meta.title,
                "shortDescription": {"text": meta.title},
                "fullDescription": {"text": meta.description},
            }
        )

    file_paths = sorted({f.file_path for f in analyze_response.findings})
    artifacts = [{"location": {"uri": _artifact_uri(p)}} for p in file_paths]

    results: list[dict[str, Any]] = []
    for finding in analyze_response.findings:
        uri = _artifact_uri(finding.file_path)
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "message": {"text": finding.title},
            "level": _severity_to_level(finding.severity),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {
                            "startLine": finding.line_start,
                            "endLine": finding.line_end,
                            **(
                                {"startColumn": finding.column}
                                if finding.column is not None
                                else {}
                            ),
                        },
                    }
                }
            ],
            "properties": {
                "cweId": finding.cwe_id,
                "owaspCategory": finding.owasp_category,
                "confidence": str(finding.confidence),
            },
        }
        results.append(result)

    driver: dict[str, Any] = {
        "name": tool_name,
        "version": tool_version,
        "rules": rules_payload,
    }
    if information_uri:
        driver["informationUri"] = information_uri

    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "artifacts": artifacts,
        "results": results,
        "properties": {
            "scanId": str(analyze_response.scan_id),
            "language": analyze_response.language,
            "stats": analyze_response.stats.model_dump(mode="json"),
        },
    }

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
