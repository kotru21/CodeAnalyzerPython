from __future__ import annotations

import json
from typing import TYPE_CHECKING

from eval.compare_enrich import enrich_rows_with_line_overlap
from eval.rule_map import load_rule_map

if TYPE_CHECKING:
    from pathlib import Path


def test_enrich_adds_line_overlap_when_both_backends(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    tid = "CASE-A"
    (raw / f"{tid}.json").write_text(
        json.dumps({"findings": [{"rule_id": "R1", "line": 3}]}),
        encoding="utf-8",
    )
    (raw / f"{tid}.semgrep.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "s1",
                        "path": f"/x/{tid}.py",
                        "start": {"line": 3},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    mpath = tmp_path / "m.yaml"
    mpath.write_text(
        "version: 1\nline_slop: 0\nrules: {}\nequivalence_rules:\n  R1: [s1]\n",
        encoding="utf-8",
    )
    cases = [{"test_id": tid, "rule_id": "R1", "type": "vulnerable"}]
    rows = [{"test_id": tid, "outcome": "TP"}]
    rm = load_rule_map(mpath)
    enrich_rows_with_line_overlap(rows, cases, rm, raw, backends_have_semgrep_and_http=True)
    assert "line_overlap" in rows[0]
    assert rows[0]["line_overlap"]["matched_lines"] == [[3, 3]]


def test_skip_row_omits_line_overlap(tmp_path: Path) -> None:
    mpath = tmp_path / "m.yaml"
    mpath.write_text("version: 1\nrules: {}\n", encoding="utf-8")
    rm = load_rule_map(mpath)
    rows = [{"test_id": "X", "outcome": "SKIP"}]
    cases = [{"test_id": "X", "rule_id": "R", "type": "vulnerable"}]
    enrich_rows_with_line_overlap(rows, cases, rm, tmp_path, backends_have_semgrep_and_http=True)
    assert "line_overlap" not in rows[0]


def test_backends_flag_false_no_op(tmp_path: Path) -> None:
    mpath = tmp_path / "m.yaml"
    mpath.write_text("version: 1\nrules: {}\n", encoding="utf-8")
    rm = load_rule_map(mpath)
    rows = [{"test_id": "X", "outcome": "TP"}]
    cases = [{"test_id": "X", "rule_id": "R", "type": "vulnerable"}]
    enrich_rows_with_line_overlap(rows, cases, rm, tmp_path, backends_have_semgrep_and_http=False)
    assert "line_overlap" not in rows[0]


def test_safe_case_empty_analyzer_lines(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    tid = "SAFE-1"
    (raw / f"{tid}.json").write_text(
        json.dumps({"findings": [{"rule_id": "R1", "line": 10}]}),
        encoding="utf-8",
    )
    (raw / f"{tid}.semgrep.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "s1",
                        "path": f"/tmp/{tid}.js",
                        "start": {"line": 10},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    mpath = tmp_path / "m.yaml"
    mpath.write_text(
        "version: 1\nrules: {}\nequivalence_rules:\n  R1: [s1]\n",
        encoding="utf-8",
    )
    cases = [{"test_id": tid, "rule_id": "R1", "type": "safe"}]
    rows = [{"test_id": tid, "outcome": "TN"}]
    rm = load_rule_map(mpath)
    enrich_rows_with_line_overlap(rows, cases, rm, raw, backends_have_semgrep_and_http=True)
    lo = rows[0]["line_overlap"]
    assert lo["analyzer_lines"] == []
    assert lo["semgrep_lines_in_map"] == [10]
    assert lo["analyzer_only_lines"] == []
    assert lo["semgrep_only_lines"] == [10]
