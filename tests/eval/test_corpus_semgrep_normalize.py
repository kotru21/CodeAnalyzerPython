from __future__ import annotations

from typing import TYPE_CHECKING

from eval.corpus_semgrep_normalize import (
    integer_lines_from_semgrep_for_relpath,
    semgrep_result_relpath,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_semgrep_result_relpath_under_corpus(tmp_path: Path) -> None:
    sub = tmp_path / "sub"
    sub.mkdir()
    f = sub / "x.js"
    f.write_text("", encoding="utf-8")
    assert semgrep_result_relpath(tmp_path, str(f.resolve())) == "sub/x.js"


def test_semgrep_result_relpath_outside_none(tmp_path: Path) -> None:
    other = tmp_path.parent / "other_corpus"
    other.mkdir(exist_ok=True)
    f = other / "x.js"
    f.write_text("", encoding="utf-8")
    assert semgrep_result_relpath(tmp_path, str(f.resolve())) is None


def _result(path: Path, check_id: str, line: int) -> dict:
    return {
        "check_id": check_id,
        "path": str(path.resolve()),
        "start": {"line": line},
    }


def test_integer_lines_filtered_by_check_id(tmp_path: Path) -> None:
    f = tmp_path / "a.js"
    f.write_text("x", encoding="utf-8")
    results = [
        _result(f, "rule.a", 1),
        _result(f, "rule.b", 2),
    ]
    lines = integer_lines_from_semgrep_for_relpath(
        results,
        tmp_path,
        "a.js",
        frozenset({"rule.a"}),
    )
    assert lines == [1]


def test_integer_lines_empty_allowlist(tmp_path: Path) -> None:
    f = tmp_path / "a.js"
    f.write_text("x", encoding="utf-8")
    results = [_result(f, "rule.a", 1)]
    lines = integer_lines_from_semgrep_for_relpath(
        results,
        tmp_path,
        "a.js",
        frozenset(),
    )
    assert lines == []


def test_integer_lines_none_allowlist_all_checks(tmp_path: Path) -> None:
    f = tmp_path / "a.js"
    f.write_text("x", encoding="utf-8")
    results = [
        _result(f, "rule.a", 1),
        _result(f, "rule.b", 3),
    ]
    lines = integer_lines_from_semgrep_for_relpath(
        results,
        tmp_path,
        "a.js",
        None,
    )
    assert lines == [1, 3]
