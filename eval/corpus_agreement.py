from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from eval.corpus_semgrep_normalize import integer_lines_from_semgrep_for_relpath
from eval.line_overlap import build_line_overlap_payload, integer_lines_from_analyzer_findings
from eval.rule_map import RuleMap


def buckets_for_policy(policy: Literal["a", "b"], rule_map: RuleMap) -> list[str]:
    if policy == "b":
        return ["ALL_MAPPED"]
    return sorted(k for k, v in rule_map.equivalence_rules.items() if v)


def _analyzer_rule_ids_in_findings(findings: list[dict[str, Any]]) -> frozenset[str]:
    out: set[str] = set()
    for f in findings:
        if isinstance(f, dict):
            rid = f.get("rule_id")
            if isinstance(rid, str):
                out.add(rid)
    return frozenset(out)


def overlap_for_file_bucket(
    *,
    line_slop: int,
    policy: Literal["a", "b"],
    bucket: str,
    rule_map: RuleMap,
    analyzer_findings: list[dict[str, Any]],
    semgrep_results_full: list[dict[str, Any]],
    corpus_root: Path,
    relpath: str,
) -> dict[str, Any]:
    if policy == "a":
        allowed = frozenset(rule_map.equivalence_rules.get(bucket, ()))
        analyzer_lines = integer_lines_from_analyzer_findings(
            analyzer_findings,
            allowed_rule_ids=frozenset({bucket}),
        )
        semgrep_lines = integer_lines_from_semgrep_for_relpath(
            semgrep_results_full,
            corpus_root,
            relpath,
            allowed,
        )
    else:
        allowed_rules = _analyzer_rule_ids_in_findings(analyzer_findings)
        analyzer_lines = integer_lines_from_analyzer_findings(
            analyzer_findings,
            allowed_rule_ids=allowed_rules,
        )
        semgrep_lines = integer_lines_from_semgrep_for_relpath(
            semgrep_results_full,
            corpus_root,
            relpath,
            None,
        )
    return build_line_overlap_payload(
        line_slop=line_slop,
        analyzer_lines=analyzer_lines,
        semgrep_lines_in_map=semgrep_lines,
    )


def aggregate_overlap_payloads(payloads: list[dict[str, Any]]) -> dict[str, int]:
    matched = 0
    ao = 0
    so = 0
    for p in payloads:
        matched += len(p.get("matched_lines") or [])
        ao += len(p.get("analyzer_only_lines") or [])
        so += len(p.get("semgrep_only_lines") or [])
    return {
        "matched_line_pairs": matched,
        "analyzer_only_lines": ao,
        "semgrep_only_lines": so,
    }
