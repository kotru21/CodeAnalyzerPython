from __future__ import annotations

from typing import TYPE_CHECKING

from eval.corpus_agreement import (
    aggregate_overlap_payloads,
    buckets_for_policy,
    overlap_for_file_bucket,
)
from eval.rule_map import RuleMap

if TYPE_CHECKING:
    from pathlib import Path


def _sg(path: Path, check_id: str, line: int) -> dict:
    return {
        "check_id": check_id,
        "path": str(path.resolve()),
        "start": {"line": line},
    }


def test_buckets_policy_a_and_b() -> None:
    rm = RuleMap(
        version=1,
        rules={},
        line_slop=0,
        equivalence_rules={"R2": ["c2"], "R1": ["c1"]},
    )
    assert buckets_for_policy("a", rm) == ["R1", "R2"]
    assert buckets_for_policy("b", rm) == ["ALL_MAPPED"]


def test_policy_a_per_bucket_overlap(tmp_path: Path) -> None:
    rm = RuleMap(
        version=1,
        rules={},
        line_slop=0,
        equivalence_rules={"R1": ["c1"], "R2": ["c2"]},
    )
    sub = tmp_path / "sub"
    sub.mkdir()
    f = sub / "f.js"
    f.write_text("//", encoding="utf-8")
    findings = [
        {"rule_id": "R1", "line": 1},
        {"rule_id": "R2", "line": 5},
    ]
    sg = [_sg(f, "c1", 1), _sg(f, "c2", 5)]
    p1 = overlap_for_file_bucket(
        line_slop=0,
        policy="a",
        bucket="R1",
        rule_map=rm,
        analyzer_findings=findings,
        semgrep_results_full=sg,
        corpus_root=tmp_path,
        relpath="sub/f.js",
    )
    p2 = overlap_for_file_bucket(
        line_slop=0,
        policy="a",
        bucket="R2",
        rule_map=rm,
        analyzer_findings=findings,
        semgrep_results_full=sg,
        corpus_root=tmp_path,
        relpath="sub/f.js",
    )
    assert p1["matched_lines"] == [[1, 1]]
    assert p2["matched_lines"] == [[5, 5]]


def test_policy_b_all_findings_and_checks(tmp_path: Path) -> None:
    rm = RuleMap(version=1, rules={}, line_slop=0, equivalence_rules={})
    f = tmp_path / "a.js"
    f.write_text("//", encoding="utf-8")
    findings = [{"rule_id": "X", "line": 2}, {"rule_id": "Y", "line": 4}]
    sg = [_sg(f, "any.c", 2), _sg(f, "any.d", 3)]
    p = overlap_for_file_bucket(
        line_slop=0,
        policy="b",
        bucket="ALL_MAPPED",
        rule_map=rm,
        analyzer_findings=findings,
        semgrep_results_full=sg,
        corpus_root=tmp_path,
        relpath="a.js",
    )
    assert p["analyzer_lines"] == [2, 4]
    assert p["semgrep_lines_in_map"] == [2, 3]
    assert p["matched_lines"] == [[2, 2]]
    assert p["analyzer_only_lines"] == [4]
    assert p["semgrep_only_lines"] == [3]


def test_aggregate_overlap_payloads_sums() -> None:
    pl = [
        {
            "matched_lines": [[1, 1]],
            "analyzer_only_lines": [2],
            "semgrep_only_lines": [9],
        },
        {
            "matched_lines": [[3, 3]],
            "analyzer_only_lines": [],
            "semgrep_only_lines": [8],
        },
    ]
    assert aggregate_overlap_payloads(pl) == {
        "matched_line_pairs": 2,
        "analyzer_only_lines": 1,
        "semgrep_only_lines": 2,
    }
