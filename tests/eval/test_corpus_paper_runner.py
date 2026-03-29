from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from eval.corpus_paper_runner import run_paper_eval
from eval.rule_map import load_rule_map


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeHttpClient:
    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def __enter__(self) -> _FakeHttpClient:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def post(self, url: str, json: dict[str, Any] | None = None, timeout: float | None = None):
        return _FakeResponse(
            {"findings": [{"rule_id": "R1", "line": 2}]},
        )


def test_run_paper_eval_line_overlap_policy_b(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = tmp_path / "corpus"
    js = corpus / "f.js"
    js.parent.mkdir(parents=True)
    js.write_text("//\nconsole.log(1);\n", encoding="utf-8")

    rm_path = tmp_path / "rule_map.yaml"
    rm_path.write_text(
        yaml.dump(
            {"version": 1, "rules": {}, "line_slop": 0, "equivalence_rules": {}},
            default_flow_style=False,
        ),
        encoding="utf-8",
    )
    rule_map = load_rule_map(rm_path)
    cfg = tmp_path / "semgrep.yaml"
    cfg.write_text("rules: []\n", encoding="utf-8")

    def fake_semgrep(
        configs: list[Path], root: Path, *, timeout_sec: int = 3600
    ) -> dict[str, Any]:
        return {
            "results": [
                {
                    "check_id": "c",
                    "path": str((root / "f.js").resolve()),
                    "start": {"line": 2},
                }
            ]
        }

    monkeypatch.setattr("eval.corpus_paper_runner.run_semgrep_json_configs", fake_semgrep)
    monkeypatch.setattr("eval.corpus_paper_runner.httpx.Client", _FakeHttpClient)
    monkeypatch.setattr("eval.corpus_paper_runner.config_bundle_hashes", lambda c: {})
    monkeypatch.setattr("eval.corpus_paper_runner.semgrep_cli_version", lambda: "0.0.0-test")

    summary = run_paper_eval(
        corpus=corpus,
        configs=[cfg],
        rule_map=rule_map,
        policy="b",
        file_mode="walk",
        analyzer_base="http://127.0.0.1:9",
        relpaths_override=["f.js"],
    )

    assert summary["matched_line_pairs"] == 1
    assert summary["analyzer_only_lines"] == 0
    assert summary["semgrep_only_lines"] == 0
    assert summary["analyzer_findings_total"] == 1
    assert summary["semgrep_findings_total"] == 1
