from __future__ import annotations

from pathlib import PurePath
from typing import Any


def integer_lines_from_analyzer_findings(
    findings: list[dict[str, Any]],
    *,
    allowed_rule_ids: frozenset[str],
) -> list[int]:
    lines: set[int] = set()
    for f in findings:
        if not isinstance(f, dict):
            continue
        rid = f.get("rule_id")
        if not isinstance(rid, str) or rid not in allowed_rule_ids:
            continue
        line = f.get("line")
        if not isinstance(line, int):
            ls = f.get("line_start")
            line = ls if isinstance(ls, int) else None
        if not isinstance(line, int):
            continue
        lines.add(line)
    return sorted(lines)


def integer_lines_from_semgrep_results(
    results: list[dict[str, Any]],
    *,
    test_id: str,
    allowed_check_ids: frozenset[str],
) -> list[int]:
    lines: set[int] = set()
    for r in results:
        if not isinstance(r, dict):
            continue
        check = r.get("check_id") or r.get("rule_id")
        if not isinstance(check, str) or check not in allowed_check_ids:
            continue
        path = r.get("path")
        if path is None:
            continue
        stem = PurePath(str(path)).stem
        if stem != test_id:
            continue
        start = r.get("start")
        if not isinstance(start, dict):
            continue
        line = start.get("line")
        if not isinstance(line, int):
            continue
        lines.add(line)
    return sorted(lines)


def greedy_match_lines(
    analyzer_lines: list[int],
    semgrep_lines: list[int],
    *,
    line_slop: int,
) -> tuple[list[list[int]], list[int], list[int]]:
    """Greedy pairing: for each analyzer line, take smallest unmatched semgrep line within slop."""
    matched: list[list[int]] = []
    used_sem: set[int] = set()
    for a in analyzer_lines:
        chosen: int | None = None
        for s in semgrep_lines:
            if s in used_sem:
                continue
            if abs(a - s) <= line_slop:
                chosen = s
                break
        if chosen is not None:
            used_sem.add(chosen)
            matched.append([a, chosen])
    matched_as = {p[0] for p in matched}
    analyzer_only = [a for a in analyzer_lines if a not in matched_as]
    semgrep_only = [s for s in semgrep_lines if s not in used_sem]
    return matched, analyzer_only, semgrep_only


def build_line_overlap_payload(
    *,
    line_slop: int,
    analyzer_lines: list[int],
    semgrep_lines_in_map: list[int],
) -> dict[str, Any]:
    matched, analyzer_only, semgrep_only = greedy_match_lines(
        analyzer_lines,
        semgrep_lines_in_map,
        line_slop=line_slop,
    )
    return {
        "line_slop_used": line_slop,
        "analyzer_lines": list(analyzer_lines),
        "semgrep_lines_in_map": list(semgrep_lines_in_map),
        "matched_lines": matched,
        "analyzer_only_lines": analyzer_only,
        "semgrep_only_lines": semgrep_only,
    }
