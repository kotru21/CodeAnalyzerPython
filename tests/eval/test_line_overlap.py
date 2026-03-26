from __future__ import annotations

from eval.line_overlap import (
    build_line_overlap_payload,
    greedy_match_lines,
    integer_lines_from_analyzer_findings,
    integer_lines_from_semgrep_results,
)


def test_greedy_slop_zero() -> None:
    matched, a_only, s_only = greedy_match_lines(
        [3, 5], [3], line_slop=0
    )
    assert matched == [[3, 3]]
    assert a_only == [5]
    assert s_only == []


def test_greedy_slop_two() -> None:
    matched, a_only, s_only = greedy_match_lines(
        [5], [7], line_slop=2
    )
    assert matched == [[5, 7]]
    assert a_only == []
    assert s_only == []

    matched2, a_only2, s_only2 = greedy_match_lines(
        [5], [7], line_slop=1
    )
    assert matched2 == []
    assert a_only2 == [5]
    assert s_only2 == [7]


def test_safe_analyzer_empty_allowed_rules() -> None:
    findings = [{"rule_id": "R1", "line": 10}]
    got = integer_lines_from_analyzer_findings(
        findings, allowed_rule_ids=frozenset()
    )
    assert got == []


def test_analyzer_filters_rule_id_and_dedupes() -> None:
    findings = [
        {"rule_id": "R1", "line": 3},
        {"rule_id": "R2", "line": 99},
        {"rule_id": "R1", "line": 3},
        {"rule_id": "R1", "line": 5},
    ]
    got = integer_lines_from_analyzer_findings(
        findings, allowed_rule_ids=frozenset({"R1"})
    )
    assert got == [3, 5]


def test_analyzer_drops_non_int_line() -> None:
    findings = [
        {"rule_id": "R1", "line": 3},
        {"rule_id": "R1", "line": None},
        {"rule_id": "R1"},
    ]
    got = integer_lines_from_analyzer_findings(
        findings, allowed_rule_ids=frozenset({"R1"})
    )
    assert got == [3]


def test_analyzer_accepts_line_start_when_line_absent() -> None:
    findings = [{"rule_id": "R1", "line_start": 6}]
    got = integer_lines_from_analyzer_findings(
        findings, allowed_rule_ids=frozenset({"R1"})
    )
    assert got == [6]


def test_semgrep_filters_check_id_and_stem() -> None:
    tid = "CASE-01"
    allow = frozenset({"rule.x"})
    results = [
        {
            "check_id": "rule.x",
            "path": f"/tmp/{tid}.py",
            "start": {"line": 2},
        },
        {
            "check_id": "rule.y",
            "path": f"/tmp/{tid}.py",
            "start": {"line": 9},
        },
        {
            "check_id": "rule.x",
            "path": "/tmp/other.py",
            "start": {"line": 2},
        },
    ]
    got = integer_lines_from_semgrep_results(
        results, test_id=tid, allowed_check_ids=allow
    )
    assert got == [2]


def test_build_line_overlap_payload_shape() -> None:
    p = build_line_overlap_payload(
        line_slop=0,
        analyzer_lines=[3, 5],
        semgrep_lines_in_map=[3],
    )
    assert p["line_slop_used"] == 0
    assert p["analyzer_lines"] == [3, 5]
    assert p["semgrep_lines_in_map"] == [3]
    assert p["matched_lines"] == [[3, 3]]
    assert p["analyzer_only_lines"] == [5]
    assert p["semgrep_only_lines"] == []
