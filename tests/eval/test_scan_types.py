from eval.scan_types import analyzer_response_to_result, findings_from_analyzer_response


def test_empty_findings() -> None:
    r = findings_from_analyzer_response({"findings": [], "stats": {"total_findings": 0}})
    assert r == []


def test_maps_rule_and_line() -> None:
    body = {
        "findings": [
            {"rule_id": "JS-SQL-001", "line": 3, "cwe_id": "CWE-89"},
        ],
        "stats": {"total_findings": 1},
    }
    out = findings_from_analyzer_response(body)
    assert len(out) == 1
    assert out[0].rule_id == "JS-SQL-001"
    assert out[0].line == 3


def test_prefers_line_start_from_api_schema() -> None:
    body = {
        "findings": [
            {"rule_id": "JS-SQL-001", "line_start": 7, "line_end": 7},
        ],
    }
    out = findings_from_analyzer_response(body)
    assert out[0].line == 7


def test_analyzer_response_to_result_ok() -> None:
    body = {"findings": [{"rule_id": "a", "line": 1}], "stats": {}}
    r = analyzer_response_to_result(body, None)
    assert r.ok
    assert r.error is None
    assert r.raw == body
    assert len(r.findings) == 1


def test_analyzer_response_to_result_http_error() -> None:
    r = analyzer_response_to_result(None, "connection refused")
    assert not r.ok
    assert r.error == "connection refused"
    assert r.findings == []
