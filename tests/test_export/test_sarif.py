from datetime import UTC, datetime
from uuid import uuid4

from analyzer.api.schemas import AnalyzeResponse, Finding, ScanStats
from analyzer.core.severity import Confidence, Severity
from analyzer.export.sarif import build_sarif_log


def test_build_sarif_log_minimal_shape() -> None:
    fid = uuid4()
    now = datetime.now(UTC)
    resp = AnalyzeResponse(
        scan_id=fid,
        status="completed",
        language="javascript",
        stats=ScanStats(),
        findings=[
            Finding(
                rule_id="JS-SQL-001",
                title="SQLi",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path="app.js",
                line_start=1,
                line_end=1,
                column=1,
                code_snippet="x",
                description="d",
                remediation="r",
                cwe_id="CWE-89",
                owasp_category="A03:2021 Injection",
            )
        ],
        created_at=now,
    )
    doc = build_sarif_log(resp, tool_name="analyzer-service", tool_version="0.1.0")
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "JS-SQL-001"
    region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1
    # tree-sitter column 1 → SARIF 1-based column 2
    assert region["startColumn"] == 2
