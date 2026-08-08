from __future__ import annotations

from typing import Any, Literal

Outcome = Literal["TP", "FP", "TN", "FN", "ERROR"]


def _finding_matches_rule(
    finding: dict[str, Any],
    rule_id: str,
    expected_cwe: str | None,
) -> bool:
    if finding.get("rule_id") != rule_id:
        return False
    return expected_cwe is None or finding.get("cwe_id") == expected_cwe


def classify_outcome(case: dict[str, Any], response: dict[str, Any] | None) -> Outcome:
    """Classify a single completed JSON response (schema B)."""
    if response is None:
        return "ERROR"
    stats = response.get("stats") or {}
    findings = response.get("findings") or []
    if not isinstance(findings, list):
        return "ERROR"

    ctype = case.get("type")
    total = stats.get("total_findings")
    if not isinstance(total, int):
        total = len(findings)

    if ctype == "safe":
        return "TN" if total == 0 else "FP"

    if ctype != "vulnerable":
        return "ERROR"

    expected_rules = case.get("expected_rule_ids")
    if expected_rules:
        for rid in expected_rules:
            if not any(isinstance(f, dict) and f.get("rule_id") == rid for f in findings):
                return "FN"
        return "TP"

    rule_id = case.get("rule_id")
    if not isinstance(rule_id, str):
        return "ERROR"
    expected_cwe = case.get("expected_cwe")
    matched = any(
        _finding_matches_rule(f, rule_id, expected_cwe) for f in findings if isinstance(f, dict)
    )
    if matched:
        return "TP"
    return "FN"


def aggregate_by_rule(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """rows: dicts with keys rule_id, outcome (TP|FP|TN|FN|ERROR)."""
    out: dict[str, dict[str, int]] = {}
    for row in rows:
        rid = row.get("rule_id")
        oc = row.get("outcome")
        if not isinstance(rid, str) or oc not in ("TP", "FP", "TN", "FN", "ERROR"):
            continue
        bucket = out.setdefault(rid, {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERROR": 0})
        bucket[oc] += 1
    return out
