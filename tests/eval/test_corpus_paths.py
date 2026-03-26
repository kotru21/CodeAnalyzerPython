from __future__ import annotations

from pathlib import Path

import pytest

from eval.corpus_paths import list_js_ts_relpaths_git, list_js_ts_relpaths_walk


def test_walk_collects_sorted_unique_relpaths(tmp_path: Path) -> None:
    (tmp_path / "a.ts").write_text("//", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.js").write_text("", encoding="utf-8")
    (tmp_path / "skip.txt").write_text("", encoding="utf-8")
    out = list_js_ts_relpaths_walk(tmp_path)
    assert out == ["a.ts", "sub/b.js"]


def test_git_mode_requires_repo(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text("", encoding="utf-8")
    with pytest.raises(RuntimeError, match="git ls-files"):
        list_js_ts_relpaths_git(tmp_path)
