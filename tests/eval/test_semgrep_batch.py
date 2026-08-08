from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

from eval.backends.semgrep_batch import batch_scan_semgrep

if TYPE_CHECKING:
    from pathlib import Path


def test_batch_groups_by_test_id(tmp_path: Path) -> None:
    cfg = tmp_path / "r"
    cfg.mkdir()
    cases = [
        {"test_id": "A1", "file_path": "a.js", "source_code": "1"},
        {"test_id": "B2", "file_path": "b.js", "source_code": "2"},
    ]
    fake_raw = {
        "results": [
            {"check_id": "r1", "path": str(tmp_path / "scan" / "A1.js"), "start": {"line": 1}},
        ],
        "errors": [],
    }

    with patch(
        "eval.backends.semgrep_batch.run_semgrep_json_configs",
        return_value=fake_raw,
    ):
        out = batch_scan_semgrep(cases, [cfg], timeout_sec=60)

    assert out["A1"].ok and len(out["A1"].findings) == 1
    assert out["B2"].ok and len(out["B2"].findings) == 0
