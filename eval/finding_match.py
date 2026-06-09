from __future__ import annotations

from typing import Any, Literal

from eval.classify import Outcome


def finding_matches_expected(
    finding: dict[str, Any],
    expected: dict[str, Any],
    *,
    line_tolerance: int = 1,
) -> bool:
    if finding.get("rule_id") != expected.get("rule_id"):
        return False
    exp_cwe = expected.get("cwe_id")
    if exp_cwe and finding.get("cwe_id") != exp_cwe:
        return False
    exp_line = expected.get("line")
    if exp_line is None:
        return True
    line_start = finding.get("line_start")
    if not isinstance(line_start, int):
        line = finding.get("line")
        line_start = line if isinstance(line, int) else None
    if not isinstance(line_start, int):
        return False
    return abs(line_start - int(exp_line)) <= line_tolerance


FindingOutcome = Literal["TP", "FP", "TN", "FN"]


def primary_outcome(outcomes: list[FindingOutcome]) -> Outcome:
    if not outcomes:
        return "ERROR"
    if "FN" in outcomes:
        return "FN"
    if "FP" in outcomes:
        return "FP"
    if "TP" in outcomes:
        return "TP"
    return "TN"


def classify_case_findings(
    case: dict[str, Any],
    response: dict[str, Any],
    *,
    line_tolerance: int = 1,
) -> list[FindingOutcome]:
    findings = [f for f in (response.get("findings") or []) if isinstance(f, dict)]
    expected_list = case.get("expected_findings")

    if expected_list is None:
        from eval.classify import classify_outcome

        single = classify_outcome(case, response)
        return [single] if single in ("TP", "FP", "TN", "FN") else []

    outcomes: list[FindingOutcome] = []
    matched_findings: set[int] = set()

    if case.get("type") == "safe":
        for i, f in enumerate(findings):
            outcomes.append("FP")
            matched_findings.add(i)
        if not findings:
            outcomes.append("TN")
        return outcomes

    for exp in expected_list:
        hit = False
        for i, f in enumerate(findings):
            if i in matched_findings:
                continue
            if finding_matches_expected(f, exp, line_tolerance=line_tolerance):
                outcomes.append("TP")
                matched_findings.add(i)
                hit = True
                break
        if not hit:
            outcomes.append("FN")

    for i, f in enumerate(findings):
        if i not in matched_findings:
            outcomes.append("FP")
    return outcomes


def expand_rows_for_metrics(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Expand per-finding outcomes into one row per outcome for metrics."""
    expanded: list[dict[str, Any]] = []
    for row in rows:
        finding_outcomes = row.get("finding_outcomes")
        if finding_outcomes:
            for oc in finding_outcomes:
                expanded.append({**row, "outcome": oc})
        else:
            expanded.append(row)
    return expanded
