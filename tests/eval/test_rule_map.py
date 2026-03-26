from __future__ import annotations

from typing import TYPE_CHECKING

from eval.rule_map import (
    collect_semgrep_configs_for_cases,
    load_rule_map,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_load_empty(tmp_path: Path) -> None:
    p = tmp_path / "m.yaml"
    p.write_text("version: 1\nrules: {}\n", encoding="utf-8")
    m = load_rule_map(p)
    assert m.rules == {}


def test_collect_union_expected_rule_ids(tmp_path: Path) -> None:
    p = tmp_path / "m.yaml"
    p.write_text(
        "version: 1\nrules:\n  A: [pack/a]\n  B: [pack/b]\n",
        encoding="utf-8",
    )
    m = load_rule_map(p)
    (tmp_path / "pack").mkdir()
    (tmp_path / "pack" / "a").mkdir()
    (tmp_path / "pack" / "b").mkdir()
    cases = [
        {"rule_id": "A", "expected_rule_ids": ["B"]},
    ]
    cfgs = collect_semgrep_configs_for_cases(cases, m, tmp_path)
    assert len(cfgs) == 2
