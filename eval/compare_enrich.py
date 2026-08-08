from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from eval.line_overlap import (
    build_line_overlap_payload,
    integer_lines_from_analyzer_findings,
    integer_lines_from_semgrep_results,
)
from eval.rule_map import (
    RuleMap,
    _rule_ids_for_case,
    allowed_semgrep_check_ids_for_case,
)

if TYPE_CHECKING:
    from pathlib import Path


def _load_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def enrich_rows_with_line_overlap(
    rows: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    rule_map: RuleMap,
    raw_dir: Path,
    *,
    backends_have_semgrep_and_http: bool,
) -> None:
    if not backends_have_semgrep_and_http:
        return
    cases_by_id = {c["test_id"]: c for c in cases if isinstance(c.get("test_id"), str)}
    for row in rows:
        if row.get("outcome") == "SKIP":
            continue
        tid = row.get("test_id")
        if not isinstance(tid, str):
            continue
        case = cases_by_id.get(tid)
        if case is None:
            continue
        analyzer_raw = _load_json_object(raw_dir / f"{tid}.json")
        semgrep_raw = _load_json_object(raw_dir / f"{tid}.semgrep.json")
        f_raw = analyzer_raw.get("findings")
        findings = f_raw if isinstance(f_raw, list) else []
        findings_dicts = [x for x in findings if isinstance(x, dict)]
        s_raw = semgrep_raw.get("results")
        results = s_raw if isinstance(s_raw, list) else []
        results_dicts = [x for x in results if isinstance(x, dict)]
        allow_checks = allowed_semgrep_check_ids_for_case(case, rule_map)
        allowed_rules = (
            frozenset() if case.get("type") == "safe" else frozenset(_rule_ids_for_case(case))
        )
        analyzer_lines = integer_lines_from_analyzer_findings(
            findings_dicts,
            allowed_rule_ids=allowed_rules,
        )
        semgrep_lines = integer_lines_from_semgrep_results(
            results_dicts,
            test_id=tid,
            allowed_check_ids=allow_checks,
        )
        row["line_overlap"] = build_line_overlap_payload(
            line_slop=rule_map.line_slop,
            analyzer_lines=analyzer_lines,
            semgrep_lines_in_map=semgrep_lines,
        )
