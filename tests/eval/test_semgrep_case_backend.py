from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

from eval.backends.semgrep_case import SemgrepCaseBackend

if TYPE_CHECKING:
    from pathlib import Path


def test_semgrep_case_backend_uses_mocked_semgrep(tmp_path: Path) -> None:
    cfg = tmp_path / "rules"
    cfg.mkdir()
    fake_json = {"results": [{"check_id": "x", "path": "f.js", "start": {"line": 2}}]}
    backend = SemgrepCaseBackend([cfg])

    with patch(
        "eval.backends.semgrep_case.run_semgrep_json_configs",
        return_value=fake_json,
    ):
        res = backend.scan_case(
            {
                "source_code": "1+1",
                "file_path": "f.js",
            }
        )
    assert res.ok
    assert len(res.findings) == 1
    assert res.findings[0].rule_id == "x"
